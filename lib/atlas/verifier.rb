# frozen_string_literal: true

require_relative "error"
require_relative "authorization"
require_relative "jwks_cache"

module Atlas
  # §7.3: five seconds either side, matching the server's minting tolerance.
  CLOCK_SKEW_SECONDS = 5

  # The outcome of a verification. A success carries the claims and the bound
  # +has?+ / +protect+ helpers; a failure carries a coarse +reason+.
  class VerifyResult
    # @return [Boolean]
    attr_reader :ok
    # @return [Hash, nil] the verified claims (string-keyed), on success.
    attr_reader :claims
    # @return [Symbol, nil] :malformed, :invalid, :no_keys, :unauthorized_party.
    attr_reader :reason

    def self.success(claims)
      new(ok: true, claims: claims)
    end

    def self.failure(reason)
      new(ok: false, reason: reason)
    end

    def initialize(ok:, claims: nil, reason: nil)
      @ok = ok
      @claims = claims
      @reason = reason
    end

    def ok?
      @ok
    end

    # True when the claims satisfy the condition (empty condition = "signed in").
    # Always false on a failed verification.
    def has?(condition = {})
      @ok && Authorization.has_from_claims?(@claims, condition)
    end

    # Assert the condition; returns the claims on success, raises
    # {Atlas::ForbiddenError} otherwise.
    def protect(condition = {})
      raise ForbiddenError.new(:unauthenticated, condition) unless @ok

      outcome = Authorization.evaluate(@claims, condition)
      raise ForbiddenError.new(outcome[:reason], condition) unless outcome[:allowed]

      @claims
    end
  end

  # §7.3 verification by customer backends.
  #
  # Verifies signature, exp/nbf with 5s clock-skew tolerance, iss, and optionally
  # azp against an allowlist. The default path is LOCAL, against cached JWKS —
  # it never calls Atlas on the hot path, so Atlas's availability never becomes
  # the customer's. +verify_online+ is the documented slow path.
  class Backend
    # @param jwks_url [String] the instance's JWKS URL.
    # @param issuer [String] expected +iss+. Required.
    # @param authorized_parties [Array<String>, nil] optional +azp+ allowlist.
    # @param secret_key [String, nil] required only for +verify_online+.
    # @param bapi_base_url [String, nil] required only for +verify_online+.
    # @param http [#call, nil] injectable requester for +verify_online+.
    # @param fetch_impl [#call, nil] injectable JWKS fetcher (tests).
    # @param now [#call, nil] clock returning epoch milliseconds (tests).
    def initialize(jwks_url:, issuer:, authorized_parties: nil, secret_key: nil,
                   bapi_base_url: nil, http: nil, fetch_impl: nil, now: nil)
      require_jwt!
      @issuer = issuer
      @authorized_parties = authorized_parties
      @secret_key = secret_key
      @bapi_base_url = bapi_base_url
      @http = http
      @jwks = JwksCache.new(url: jwks_url, fetch_impl: fetch_impl, now: now)
    end

    # Verify locally. No network call unless the +kid+ is unknown, and at most
    # one of those a minute.
    # @return [VerifyResult]
    def verify(token)
      return VerifyResult.failure(:malformed) if token.nil? || token.split(".").length != 3

      keys = @jwks.get(Atlas.read_kid(token))
      return VerifyResult.failure(:no_keys) if keys.nil? || keys["keys"].nil? || keys["keys"].empty?

      begin
        jwk_set = JWT::JWK::Set.new(keys)
        payload, = JWT.decode(
          token, nil, true,
          algorithms: ["RS256"],
          iss: @issuer,
          verify_iss: true,
          jwks: jwk_set,
          # exp/nbf tolerance, matching the server's minting skew.
          leeway: CLOCK_SKEW_SECONDS
        )
        claims = payload
      rescue JWT::DecodeError, StandardError
        # One reason for every failure — telling a caller which check failed
        # helps a forger more than a developer.
        return VerifyResult.failure(:invalid)
      end

      # §13.1 token-confusion guard: reject an OP access/id token replayed as a
      # session. An absent token_use/aud is a valid (legacy) session.
      token_use = claims["token_use"]
      return VerifyResult.failure(:invalid) if (!token_use.nil? && token_use != "session") || !claims["aud"].nil?

      if @authorized_parties && !@authorized_parties.empty?
        azp = claims["azp"]
        return VerifyResult.failure(:unauthorized_party) if azp.nil? || !@authorized_parties.include?(azp)
      end

      VerifyResult.success(claims)
    end

    # §7.3 the documented slow path: ask Atlas whether the session is still live.
    # Costs a round trip on every call. Fails CLOSED on an outage.
    # @return [VerifyResult]
    def verify_online(token)
      local = verify(token)
      return local unless local.ok?

      if @secret_key.nil? || @bapi_base_url.nil?
        raise ConfigurationError,
              "verify_online needs secret_key and bapi_base_url. Without them it " \
              "would silently fall back to local verification."
      end

      begin
        status, text = post_verify(token)
        return VerifyResult.failure(:invalid) unless status.between?(200, 299)

        body = JSON.parse(text)
        body["verified"] ? local : VerifyResult.failure(:invalid)
      rescue StandardError
        # The caller reached for verify_online precisely because a stale answer
        # was unacceptable, so an outage returns a failure, never the local pass.
        VerifyResult.failure(:invalid)
      end
    end

    # Verify whatever a request carries. Accepts a Hash of headers (string keys)
    # or any object responding to +get(name)+. The Authorization header wins over
    # a +__session+ cookie.
    # @return [VerifyResult]
    def authenticate_request(headers)
      header = read_header(headers, "authorization")
      cookie = read_header(headers, "cookie")

      bearer = header&.start_with?("Bearer ") ? header[7..] : nil
      from_cookie = cookie ? read_cookie(cookie, "__session") : nil

      token = bearer || from_cookie
      return VerifyResult.failure(:malformed) if token.nil?

      verify(token)
    end

    private

    def require_jwt!
      require "jwt"
    rescue LoadError
      raise Atlas::Error,
            "Token verification needs the `jwt` gem. Add `gem \"jwt\"` to your Gemfile."
    end

    def post_verify(token)
      url = "#{@bapi_base_url.sub(%r{/+\z}, '')}/v1/tokens/verify"
      headers = {
        "authorization" => "Bearer #{@secret_key}",
        "content-type" => "application/json"
      }
      payload = JSON.generate({ token: token })
      if @http
        @http.call("POST", url, headers, payload)
      else
        NetHTTPRequester.new.call("POST", url, headers, payload)
      end
    end

    def read_header(headers, name)
      if headers.respond_to?(:get)
        headers.get(name)
      elsif headers.respond_to?(:[])
        headers[name] || headers[name.downcase] || headers[name.to_sym]
      end
    end

    def read_cookie(header, name)
      header.split(";").each do |part|
        key, *rest = part.strip.split("=")
        return rest.join("=") if key == name
      end
      nil
    end
  end

  # §8.2 standalone helpers for code that already holds a claims hash.
  module_function

  def has_permission?(claims, permission)
    Authorization.has_from_claims?(claims, permission: permission)
  end

  def has_role?(claims, role)
    Authorization.has_from_claims?(claims, role: role)
  end

  def has?(claims, condition = {})
    Authorization.has_from_claims?(claims, condition)
  end

  def protect(claims, condition = {})
    outcome = Authorization.evaluate(claims, condition)
    raise ForbiddenError.new(outcome[:reason], condition) unless outcome[:allowed]

    claims
  end
end
