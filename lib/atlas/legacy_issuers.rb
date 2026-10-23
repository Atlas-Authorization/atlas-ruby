# frozen_string_literal: true

require "json"
require "time"
require "uri"

module Atlas
  # Accepting your OLD auth provider's JWTs during a cutover — today, Better
  # Auth's +jwt+ plugin tokens.
  #
  # With +legacy_issuers:+ on {Atlas::Backend}, a token whose +iss+ is one of
  # these issuers is verified against THAT issuer's key set (the JWKS you
  # imported into Atlas, or the old app's +/api/auth/jwks+) for a bounded
  # window, and its +sub+ (the Better Auth user id) is mapped to the Atlas user
  # id — Atlas keeps the Better Auth id as the user's +external_id+. After
  # +until+, those tokens are refused like any other foreign token.
  #
  #   Atlas::Backend.new(jwks_url: ..., issuer: ..., secret_key: "sk_live_...",
  #     legacy_issuers: [{ issuer: "https://app.example.com", jwks_url: "https://app.example.com/api/auth/jwks",
  #                        audience: "https://app.example.com", until: Time.utc(2027, 1, 31) }])
  #
  # Entry keys: +issuer+ (required), +until+ (required: Time, epoch ms or
  # ISO-8601), exactly one of +jwks+ (a key-set Hash) / +jwks_url+, +audience+
  # (String or Array), +algorithms+ (default {BETTER_AUTH_JWT_ALGS}),
  # +resolve_subject+ (a callable +(sub, claims) -> atlas_user_id | nil+; default
  # a Backend API lookup by +external_id+, cached 5 minutes).
  class LegacyIssuerVerifier
    # The Better Auth +jwt+ plugin's key algorithms.
    BETTER_AUTH_JWT_ALGS = %w[EdDSA ES256 ES512 RS256 PS256].freeze
    # How long a resolved sub → Atlas id mapping is reused (ms).
    SUBJECT_TTL_MS = 5 * 60_000
    # Cap on cached subjects.
    SUBJECT_CACHE_MAX = 10_000
    DEFAULT_API_URL = "https://api.atlasauth.net"

    def self.until_ms(value)
      case value
      when Time then (value.to_f * 1000).to_i
      when Integer, Float then value.to_i
      when String then (Time.iso8601(value).to_f * 1000).to_i
      else 0
      end
    rescue ArgumentError
      0
    end

    # The UNVERIFIED +iss+ of a compact JWT, for routing only.
    def self.peek_issuer(token)
      payload = JSON.parse(Atlas::DPoP.b64u_decode(token.to_s.split(".")[1].to_s))
      payload.is_a?(Hash) && payload["iss"].is_a?(String) ? payload["iss"] : nil
    rescue StandardError
      nil
    end

    def initialize(issuers, atlas_issuer:, secret_key: nil, api_url: nil, http: nil, fetch_impl: nil, now: nil,
                   leeway: 5)
      @now = now || -> { (Time.now.to_f * 1000).to_i }
      @leeway = leeway
      @secret_key = secret_key
      @api_url = (api_url || DEFAULT_API_URL).sub(%r{/+\z}, "")
      @http = http
      @mutex = Mutex.new
      @subjects = {}
      @issuers = issuers.map { |e| normalize(e) }
      @keysets = {}
      @issuers.each do |e|
        raise ConfigurationError, "legacy_issuers: every entry needs issuer." if e[:issuer].to_s.empty?
        raise ConfigurationError, "A legacy issuer cannot be the Atlas issuer itself." if e[:issuer] == atlas_issuer
        if e[:jwks].nil? == e[:jwks_url].to_s.empty?
          raise ConfigurationError, "legacy_issuers: \"#{e[:issuer]}\" needs exactly one of jwks or jwks_url."
        end
        if self.class.until_ms(e[:until]).zero?
          raise ConfigurationError, "legacy_issuers: \"#{e[:issuer]}\" needs a valid until (the end of the window)."
        end
        if e[:resolve_subject].nil? && secret_key.to_s.empty?
          raise ConfigurationError,
                "legacy_issuers: \"#{e[:issuer]}\" maps its sub to an Atlas user through the Backend API, " \
                "which needs secret_key on Atlas::Backend — or give the issuer a resolve_subject."
        end
        @keysets[e[:issuer]] = if e[:jwks_url].to_s.empty?
                                 stringify(e[:jwks])
                               else
                                 JwksCache.new(url: e[:jwks_url], fetch_impl: fetch_impl, now: now)
                               end
      end
    end

    # The entry for +iss+ when its window is still open, or nil.
    def match(iss)
      return nil if iss.nil?

      entry = @issuers.find { |e| e[:issuer] == iss }
      entry && self.class.until_ms(entry[:until]) > @now.call ? entry : nil
    end

    # @return [Atlas::VerifyResult]
    def verify(token, entry)
      head_b64, body_b64, sig_b64 = token.split(".")
      header = JSON.parse(Atlas::DPoP.b64u_decode(head_b64))
      alg = header["alg"]
      kid = header["kid"].is_a?(String) ? header["kid"] : nil
      return VerifyResult.failure(:invalid) unless (entry[:algorithms] || BETTER_AUTH_JWT_ALGS).include?(alg)

      source = @keysets[entry[:issuer]]
      keyset = source.is_a?(JwksCache) ? source.get(kid) : source
      keys = keyset.is_a?(Hash) ? Array(keyset["keys"]) : []
      return VerifyResult.failure(:no_keys) if keys.empty?

      sig = Atlas::DPoP.b64u_decode(sig_b64.to_s)
      input = "#{head_b64}.#{body_b64}"
      verified = keys.any? do |jwk|
        jwk.is_a?(Hash) && (kid.nil? || jwk["kid"] == kid) && Atlas::DPoP.verify_signature(jwk, alg, input, sig)
      end
      return VerifyResult.failure(:invalid) unless verified

      claims = JSON.parse(Atlas::DPoP.b64u_decode(body_b64))
      return VerifyResult.failure(:invalid) unless claims.is_a?(Hash) && valid_claims?(claims, entry)

      legacy_sub = claims["sub"].is_a?(String) && !claims["sub"].empty? ? claims["sub"] : claims["id"]
      return VerifyResult.failure(:invalid) unless legacy_sub.is_a?(String) && !legacy_sub.empty?

      atlas_id = resolve(legacy_sub, claims, entry)
      return VerifyResult.failure(:invalid) if atlas_id.nil? || atlas_id.to_s.empty?

      VerifyResult.success(claims.merge(
        "sub" => atlas_id,
        "sid" => claims["sid"].is_a?(String) ? claims["sid"] : "",
        "external_id" => legacy_sub,
        "legacy" => { "kind" => entry[:kind] || "better_auth", "issuer" => entry[:issuer], "sub" => legacy_sub },
      ))
    rescue StandardError
      VerifyResult.failure(:invalid)
    end

    private

    def normalize(entry)
      entry.to_h.transform_keys(&:to_sym)
    end

    def stringify(jwks)
      JSON.parse(JSON.generate(jwks))
    end

    def valid_claims?(claims, entry)
      now = @now.call / 1000
      return false unless claims["iss"] == entry[:issuer]
      # A legacy token without an expiry would outlive the window it is accepted in.
      return false unless claims["exp"].is_a?(Numeric) && now <= claims["exp"] + @leeway
      return false if claims["nbf"].is_a?(Numeric) && now + @leeway < claims["nbf"]

      unless entry[:audience].nil?
        want = Array(entry[:audience])
        got = Array(claims["aud"])
        return false if (want & got).empty?
      end
      true
    end

    def resolve(legacy_sub, claims, entry)
      if entry[:resolve_subject]
        begin
          return entry[:resolve_subject].call(legacy_sub, claims)
        rescue StandardError
          return nil
        end
      end
      key = "#{entry[:issuer]}\u0000#{legacy_sub}"
      now = @now.call
      @mutex.synchronize do
        hit = @subjects[key]
        return hit[0] if hit && now - hit[1] < SUBJECT_TTL_MS
      end
      url = "#{@api_url}/v1/users?#{URI.encode_www_form(external_id: legacy_sub, limit: 1)}"
      headers = { "authorization" => "Bearer #{@secret_key}", "accept" => "application/json" }
      status, text = (@http || NetHTTPRequester.new).call("GET", url, headers, nil)
      return nil unless status.between?(200, 299) # not cached: a transient failure should not stick

      first = Array(JSON.parse(text.to_s)["data"]).first
      id = first.is_a?(Hash) && first["id"].is_a?(String) && !first["id"].empty? ? first["id"] : nil
      @mutex.synchronize do
        @subjects.clear if @subjects.size >= SUBJECT_CACHE_MAX
        @subjects[key] = [id, now]
      end
      id
    rescue StandardError
      nil
    end
  end
end
