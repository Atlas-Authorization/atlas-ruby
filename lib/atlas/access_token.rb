# frozen_string_literal: true

require "json"
require "uri"
require_relative "error"
require_relative "jwks_cache"
require_relative "verifier"
require_relative "dpop"
require_relative "introspection"

module Atlas
  # The verdict of {AccessTokenVerifier#verify}. On success +ok?+ is true and
  # +claims+, +scopes+, +subject+, +client_id+ and +dpop_bound+ are set.
  # Otherwise +status+ (400, 401 or 403), +error+ (nil when no token was sent),
  # +description+ and +www_authenticate+ (set it as the response header
  # verbatim) describe it. +dpop_nonce+, when set, goes in the +DPoP-Nonce+
  # response header (on success and refusal alike).
  class AccessTokenResult
    attr_reader :status, :error, :description, :www_authenticate, :claims, :scopes, :subject, :client_id,
                :dpop_nonce

    def initialize(ok:, status: 200, error: nil, description: "", www_authenticate: "", claims: {},
                   scopes: [], subject: "", client_id: nil, dpop_bound: false, dpop_nonce: nil)
      @ok = ok
      @status = status
      @error = error
      @description = description
      @www_authenticate = www_authenticate
      @claims = claims
      @scopes = scopes
      @subject = subject
      @client_id = client_id
      @dpop_bound = dpop_bound
      @dpop_nonce = dpop_nonce
    end

    def ok?
      @ok
    end

    # Whether the token was DPoP-bound (and its proof checked).
    def dpop_bound?
      @dpop_bound
    end
  end

  # Verifies Atlas-issued OAuth access tokens for your own API (an OAuth 2.0
  # resource server) locally against the instance JWKS — RS256 or ES256, nothing
  # else: issuer, expiry, that it IS an access token, that its +aud+ names your
  # API (RFC 8707) and the scopes a route needs. A refusal carries the RFC 6750 /
  # RFC 9728 +WWW-Authenticate+ challenge. Sender-constrained tokens (RFC 9449
  # DPoP) are enforced: a token bound to a key (+cnf.jkt+) is accepted only
  # with the +DPoP+ scheme and a valid DPoP proof from that key, never as a
  # plain Bearer token.
  class AccessTokenVerifier
    AUTHZ = /\A(Bearer|DPoP)\s+([A-Za-z0-9\-._~+\/]+=*)\z/i

    # @param issuer [String] your instance issuer. Required.
    # @param audience [String, Array<String>, false] your API identifier(s);
    #   +false+ only to skip the audience check.
    # @param required_scopes [Array<String>] scopes every request must carry.
    # @param jwks_url [String, nil] defaults to +issuer/.well-known/jwks.json+.
    # @param resource_metadata_url [String, nil] advertised as +resource_metadata+.
    # @param require_dpop [Boolean] refuse every token that is not DPoP-bound and
    #   challenge with the +DPoP+ scheme.
    # @param public_origin [String, nil] this API's public origin, used for the
    #   DPoP +htu+ when the request URL is a path (set it behind a proxy).
    # @param dpop_replay_store [#claim, nil] records proof +jti+s; default
    #   {DPoP::MemoryReplayStore} (one process).
    # @param dpop_nonces [#current, #valid?, nil] when set, every proof must carry a
    #   nonce it issued; others are refused with +use_dpop_nonce+.
    # @param introspection [Hash, Introspector, nil] validate opaque access tokens
    #   (and, with +introspect_jwts: true+, JWTs too) at Atlas's RFC 7662
    #   endpoint: +{ client_id:, client_secret:, endpoint:, cache_ttl:,
    #   negative_cache_ttl:, cache_max:, introspect_jwts: }+.
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(issuer:, audience:, required_scopes: [], jwks_url: nil, resource_metadata_url: nil,
                   realm: nil, fetch_impl: nil, now: nil, require_dpop: false, public_origin: nil,
                   dpop_replay_store: nil, dpop_nonces: nil, introspection: nil)
      require "jwt"
      raise ArgumentError, "AccessTokenVerifier needs an issuer" if issuer.to_s.empty?
      if audience != false && Array(audience).empty?
        raise ArgumentError, "AccessTokenVerifier needs an audience (or audience: false)"
      end

      @issuer = issuer.sub(%r{/+\z}, "")
      @audiences = audience == false ? nil : Array(audience)
      @required = Array(required_scopes)
      @resource_metadata_url = resource_metadata_url
      @realm = realm
      @now = now
      @require_dpop = require_dpop
      @public_origin = public_origin
      @nonces = dpop_nonces
      @replay = dpop_replay_store || DPoP::MemoryReplayStore.new(now: -> { now_seconds })
      @jwks = JwksCache.new(url: jwks_url || "#{@issuer}/.well-known/jwks.json", fetch_impl: fetch_impl, now: now)
      @introspector = case introspection
                      when nil then nil
                      when Introspector then introspection
                      else Introspector.new(issuer: @issuer, now: now, **introspection)
                      end
    end

    # The {Introspector} in use, when +introspection+ was given.
    attr_reader :introspector

    # Verify an +Authorization+ header value (+Bearer+ or +DPoP+ scheme).
    # +method+, +url+ (absolute, or a path resolved against +public_origin+) and
    # +dpop+ (the +DPoP+ header) are what a DPoP proof is checked against.
    # Never raises for a bad token.
    # @return [AccessTokenResult]
    def verify(authorization, required_scopes: [], method: "GET", url: "", dpop: nil)
      required = @required + Array(required_scopes)
      nonce = @nonces&.current
      deny = ->(status, error, desc, scheme = nil) { refuse(status, error, desc, required, scheme, nonce) }
      value = authorization.to_s.strip
      return deny.call(401, nil, "Authentication required.") if value.empty?

      m = AUTHZ.match(value)
      return deny.call(400, "invalid_request", "Malformed Authorization header.") if m.nil?

      presented_dpop = m[1].casecmp("dpop").zero?

      token = m[2]
      invalid = "The access token is invalid or expired."
      is_jwt = token.split(".").length == 3
      if !is_jwt || @introspector&.introspect_jwts
        # An opaque token (or a JWT the caller wants checked live) is validated
        # by Atlas itself.
        if @introspector.nil?
          return deny.call(401, "invalid_token",
                           "The access token is not a JWT; configure `introspection` to accept opaque tokens.")
        end

        begin
          claims = @introspector.introspect(token)
        rescue Introspector::Error
          return deny.call(401, "invalid_token", "The access token could not be validated right now.")
        end
        return deny.call(401, "invalid_token", invalid) if claims.nil?
        if claims.key?("iss") && claims["iss"].to_s.sub(%r{/+\z}, "") != @issuer
          return deny.call(401, "invalid_token", "The access token was issued by another authorization server.")
        end
        if claims["exp"].is_a?(Numeric) && claims["exp"] + CLOCK_SKEW_SECONDS <= now_seconds
          return deny.call(401, "invalid_token", invalid)
        end
      else
        keys = @jwks.get(Atlas.read_kid(token))
        if keys.nil? || keys["keys"].nil? || keys["keys"].empty?
          return deny.call(401, "invalid_token", "No signing keys are available to verify the token.")
        end

        begin
          claims, = JWT.decode(token, nil, true, algorithms: SIGNING_ALGS, iss: @issuer, verify_iss: true,
                                                 jwks: JWT::JWK::Set.new(keys), leeway: CLOCK_SKEW_SECONDS,
                                                 required_claims: ["exp"])
        rescue JWT::DecodeError, StandardError
          return deny.call(401, "invalid_token", invalid)
        end
      end

      token_use = claims["token_use"]
      if !token_use.nil? && token_use != "access_token"
        return deny.call(401, "invalid_token", "The token is not an access token.")
      end
      if @audiences && (Array(claims["aud"]) & @audiences).empty?
        return deny.call(401, "invalid_token", "The access token was not issued for this resource.")
      end
      if @now && claims["exp"].is_a?(Numeric) && now_seconds > claims["exp"] + CLOCK_SKEW_SECONDS
        return deny.call(401, "invalid_token", "The access token is invalid or expired.")
      end

      # Sender constraint (RFC 9449). A bound token is only ever a DPoP token.
      jkt = nil
      if claims["cnf"].is_a?(Hash) && claims["cnf"].key?("jkt")
        jkt = claims["cnf"]["jkt"]
        unless jkt.is_a?(String) && !jkt.empty?
          return deny.call(401, "invalid_token", "The access token is invalid or expired.")
        end
      end
      if jkt || @require_dpop || presented_dpop
        if jkt.nil?
          return deny.call(401, "invalid_token", "This resource requires a DPoP-bound access token.", "DPoP")
        end
        unless presented_dpop
          return deny.call(401, "invalid_token", "A DPoP-bound access token must be sent with the DPoP scheme.",
                           "DPoP")
        end
        if dpop.nil? || dpop.to_s.strip.empty?
          return deny.call(401, "invalid_dpop_proof", "A DPoP proof is required.", "DPoP")
        end

        refusal = DPoP.check_proof(dpop.to_s.strip, token: token, jkt: jkt, method: (method || "GET").to_s.upcase,
                                                    url: url.to_s, public_origin: @public_origin, now: now_seconds,
                                                    replay: @replay, nonces: @nonces)
        return deny.call(401, refusal[0], refusal[1], "DPoP") if refusal
      end

      scopes = claims["scope"].is_a?(String) ? claims["scope"].split : []
      granted = scopes + Array(claims["permissions"]).grep(String)
      missing = required - granted
      unless missing.empty?
        return deny.call(403, "insufficient_scope",
                         "The access token is missing the required scope(s): #{missing.join(' ')}.")
      end

      AccessTokenResult.new(ok: true, claims: claims, scopes: scopes, subject: claims["sub"].to_s,
                            client_id: claims["client_id"] || claims["azp"], dpop_bound: !jkt.nil?,
                            dpop_nonce: nonce)
    end

    # Verify a Rack request: the +Authorization+ and +DPoP+ headers, method and URL.
    # @return [AccessTokenResult]
    def verify_rack(env, required_scopes: [])
      dpop = env["HTTP_DPOP"]
      dpop = nil if dpop&.include?(",") # several DPoP headers are no proof at all
      verify(env["HTTP_AUTHORIZATION"], required_scopes: required_scopes, method: env["REQUEST_METHOD"],
                                        url: rack_url(env), dpop: dpop)
    end

    private

    def now_seconds
      @now ? @now.call / 1000.0 : Time.now.to_f
    end

    def rack_url(env)
      path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      path = "/" if path.empty?
      path += "?#{env['QUERY_STRING']}" unless env["QUERY_STRING"].to_s.empty?
      return path if @public_origin

      scheme = env["rack.url_scheme"] || "http"
      host = env["HTTP_HOST"] || "#{env['SERVER_NAME']}:#{env['SERVER_PORT']}"
      "#{scheme}://#{host}#{path}"
    end

    def refuse(status, error, description, required, scheme, nonce)
      scope = error.nil? || error == "insufficient_scope" ? required : nil
      AccessTokenResult.new(
        ok: false, status: status, error: error, description: description, dpop_nonce: nonce,
        www_authenticate: Atlas.build_www_authenticate(realm: @realm, error: error, description: description,
                                                       scope: scope, resource_metadata_url: @resource_metadata_url,
                                                       scheme: scheme || (@require_dpop ? "DPoP" : "Bearer"))
      )
    end
  end

  # Rack middleware protecting every request with an Atlas access token
  # (Bearer, or DPoP with its proof). A refusal answers with the verifier's
  # status and +WWW-Authenticate+ challenge; a success leaves the
  # {AccessTokenResult} at +env["atlas.access_token"]+. The verifier's
  # +DPoP-Nonce+, when it issues nonces, is set on every response.
  class AccessTokenGuard
    ENV_KEY = "atlas.access_token"

    def initialize(app, verifier:, required_scopes: [])
      @app = app
      @verifier = verifier
      @required_scopes = required_scopes
    end

    def call(env)
      result = @verifier.verify_rack(env, required_scopes: @required_scopes)
      unless result.ok?
        body = JSON.generate({ error: result.error || "unauthorized" })
        headers = { "content-type" => "application/json", "www-authenticate" => result.www_authenticate }
        headers["dpop-nonce"] = result.dpop_nonce if result.dpop_nonce
        return [result.status, headers, [body]]
      end

      env[ENV_KEY] = result
      status, headers, body = @app.call(env)
      if result.dpop_nonce
        headers = headers.dup
        headers["dpop-nonce"] = result.dpop_nonce
      end
      [status, headers, body]
    end
  end

  module_function

  # An RFC 6750 / RFC 9449 / RFC 9728 challenge (+scheme+ "Bearer" or "DPoP";
  # a DPoP challenge also lists the accepted proof algorithms). Without +error+
  # it is the bare "authentication required" challenge (no token was sent).
  def build_www_authenticate(realm: nil, error: nil, description: nil, scope: nil, resource_metadata_url: nil,
                             scheme: "Bearer")
    q = ->(v) { "\"#{v.to_s.gsub(/["\\]/) { |c| "\\#{c}" }}\"" }
    parts = []
    parts << "realm=#{q.call(realm)}" if realm
    if error
      parts << "error=#{q.call(error)}"
      parts << "error_description=#{q.call(description)}" if description
    end
    parts << "scope=#{q.call(Array(scope).join(' '))}" if scope && !Array(scope).empty?
    parts << "resource_metadata=#{q.call(resource_metadata_url)}" if resource_metadata_url
    scheme = scheme == "DPoP" ? "DPoP" : "Bearer"
    parts << "algs=#{q.call(DPoP::ALGS.join(' '))}" if scheme == "DPoP"
    parts.empty? ? scheme : "#{scheme} #{parts.join(', ')}"
  end

  # The RFC 9728 protected-resource metadata document for your API.
  # +dpop_bound_access_tokens_required+ advertises that tokens must be
  # DPoP-bound (pair it with +require_dpop+).
  def protected_resource_metadata(resource:, issuer:, scopes_supported: nil, dpop_bound_access_tokens_required: false)
    doc = {
      "resource" => resource,
      "authorization_servers" => [issuer.sub(%r{/+\z}, "")],
      "bearer_methods_supported" => ["header"]
    }
    doc["scopes_supported"] = scopes_supported if scopes_supported && !scopes_supported.empty?
    doc["dpop_signing_alg_values_supported"] = DPoP::ALGS.dup
    doc["dpop_bound_access_tokens_required"] = true if dpop_bound_access_tokens_required
    doc
  end

  # The RFC 9728 well-known path for a resource identifier.
  def protected_resource_metadata_path(resource)
    "/.well-known/oauth-protected-resource#{URI.parse(resource).path.sub(%r{/+\z}, '')}"
  end
end
