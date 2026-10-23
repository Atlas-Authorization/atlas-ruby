# frozen_string_literal: true

require "json"
require "uri"
require_relative "error"
require_relative "jwks_cache"
require_relative "verifier"

module Atlas
  # The verdict of {AccessTokenVerifier#verify}. On success +ok?+ is true and
  # +claims+, +scopes+, +subject+ and +client_id+ are set. Otherwise +status+
  # (400, 401 or 403), +error+ (nil when no token was sent), +description+ and
  # +www_authenticate+ (set it as the response header verbatim) describe it.
  class AccessTokenResult
    attr_reader :status, :error, :description, :www_authenticate, :claims, :scopes, :subject, :client_id

    def initialize(ok:, status: 200, error: nil, description: "", www_authenticate: "", claims: {},
                   scopes: [], subject: "", client_id: nil)
      @ok = ok
      @status = status
      @error = error
      @description = description
      @www_authenticate = www_authenticate
      @claims = claims
      @scopes = scopes
      @subject = subject
      @client_id = client_id
    end

    def ok?
      @ok
    end
  end

  # Verifies Atlas-issued OAuth access tokens for your own API (an OAuth 2.0
  # resource server) locally against the instance JWKS — RS256 or ES256, nothing
  # else: issuer, expiry, that it IS an access token, that its +aud+ names your
  # API (RFC 8707) and the scopes a route needs. A refusal carries the RFC 6750 /
  # RFC 9728 +WWW-Authenticate+ challenge. DPoP-bound tokens (+cnf.jkt+) are
  # refused: this verifier checks Bearer tokens only.
  class AccessTokenVerifier
    AUTHZ = /\A(Bearer|DPoP)\s+([A-Za-z0-9\-._~+\/]+=*)\z/i

    # @param issuer [String] your instance issuer. Required.
    # @param audience [String, Array<String>, false] your API identifier(s);
    #   +false+ only to skip the audience check.
    # @param required_scopes [Array<String>] scopes every request must carry.
    # @param jwks_url [String, nil] defaults to +issuer/.well-known/jwks.json+.
    # @param resource_metadata_url [String, nil] advertised as +resource_metadata+.
    def initialize(issuer:, audience:, required_scopes: [], jwks_url: nil, resource_metadata_url: nil,
                   realm: nil, fetch_impl: nil, now: nil)
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
      @jwks = JwksCache.new(url: jwks_url || "#{@issuer}/.well-known/jwks.json", fetch_impl: fetch_impl, now: now)
    end

    # Verify an +Authorization+ header value. Never raises for a bad token.
    # @return [AccessTokenResult]
    def verify(authorization, required_scopes: [])
      required = @required + Array(required_scopes)
      value = authorization.to_s.strip
      return refuse(401, nil, "Authentication required.", required) if value.empty?

      m = AUTHZ.match(value)
      return refuse(400, "invalid_request", "Malformed Authorization header.", required) if m.nil?
      if m[1].casecmp("dpop").zero?
        return refuse(401, "invalid_token", "DPoP-bound access tokens are not accepted here.", required)
      end

      token = m[2]
      return refuse(401, "invalid_token", "The access token is malformed.", required) if token.split(".").length != 3

      keys = @jwks.get(Atlas.read_kid(token))
      if keys.nil? || keys["keys"].nil? || keys["keys"].empty?
        return refuse(401, "invalid_token", "No signing keys are available to verify the token.", required)
      end

      begin
        claims, = JWT.decode(token, nil, true, algorithms: SIGNING_ALGS, iss: @issuer, verify_iss: true,
                                               jwks: JWT::JWK::Set.new(keys), leeway: CLOCK_SKEW_SECONDS,
                                               required_claims: ["exp"])
      rescue JWT::DecodeError, StandardError
        return refuse(401, "invalid_token", "The access token is invalid or expired.", required)
      end

      token_use = claims["token_use"]
      if !token_use.nil? && token_use != "access_token"
        return refuse(401, "invalid_token", "The token is not an access token.", required)
      end
      if @audiences && (Array(claims["aud"]) & @audiences).empty?
        return refuse(401, "invalid_token", "The access token was not issued for this resource.", required)
      end
      if claims["cnf"].is_a?(Hash) && claims["cnf"].key?("jkt")
        return refuse(401, "invalid_token", "DPoP-bound access tokens are not accepted here.", required)
      end

      scopes = claims["scope"].is_a?(String) ? claims["scope"].split : []
      granted = scopes + Array(claims["permissions"]).grep(String)
      missing = required - granted
      unless missing.empty?
        return refuse(403, "insufficient_scope",
                    "The access token is missing the required scope(s): #{missing.join(' ')}.", required)
      end

      AccessTokenResult.new(ok: true, claims: claims, scopes: scopes, subject: claims["sub"].to_s,
                            client_id: claims["client_id"] || claims["azp"])
    end

    private

    def refuse(status, error, description, required)
      scope = error.nil? || error == "insufficient_scope" ? required : nil
      AccessTokenResult.new(
        ok: false, status: status, error: error, description: description,
        www_authenticate: Atlas.build_www_authenticate(realm: @realm, error: error, description: description,
                                                       scope: scope, resource_metadata_url: @resource_metadata_url)
      )
    end
  end

  # Rack middleware protecting every request with an Atlas access token. A
  # refusal answers with the verifier's status and +WWW-Authenticate+ challenge;
  # a success leaves the {AccessTokenResult} at +env["atlas.access_token"]+.
  class AccessTokenGuard
    ENV_KEY = "atlas.access_token"

    def initialize(app, verifier:, required_scopes: [])
      @app = app
      @verifier = verifier
      @required_scopes = required_scopes
    end

    def call(env)
      result = @verifier.verify(env["HTTP_AUTHORIZATION"], required_scopes: @required_scopes)
      unless result.ok?
        body = JSON.generate({ error: result.error || "unauthorized" })
        return [result.status, { "content-type" => "application/json", "www-authenticate" => result.www_authenticate }, [body]]
      end

      env[ENV_KEY] = result
      @app.call(env)
    end
  end

  module_function

  # An RFC 6750 / RFC 9728 Bearer challenge. Without +error+ it is the bare
  # "authentication required" challenge (no token was sent).
  def build_www_authenticate(realm: nil, error: nil, description: nil, scope: nil, resource_metadata_url: nil)
    q = ->(v) { "\"#{v.to_s.gsub(/["\\]/) { |c| "\\#{c}" }}\"" }
    parts = []
    parts << "realm=#{q.call(realm)}" if realm
    if error
      parts << "error=#{q.call(error)}"
      parts << "error_description=#{q.call(description)}" if description
    end
    parts << "scope=#{q.call(Array(scope).join(' '))}" if scope && !Array(scope).empty?
    parts << "resource_metadata=#{q.call(resource_metadata_url)}" if resource_metadata_url
    parts.empty? ? "Bearer" : "Bearer #{parts.join(', ')}"
  end

  # The RFC 9728 protected-resource metadata document for your API.
  def protected_resource_metadata(resource:, issuer:, scopes_supported: nil)
    doc = {
      "resource" => resource,
      "authorization_servers" => [issuer.sub(%r{/+\z}, "")],
      "bearer_methods_supported" => ["header"]
    }
    doc["scopes_supported"] = scopes_supported if scopes_supported && !scopes_supported.empty?
    doc
  end

  # The RFC 9728 well-known path for a resource identifier.
  def protected_resource_metadata_path(resource)
    "/.well-known/oauth-protected-resource#{URI.parse(resource).path.sub(%r{/+\z}, '')}"
  end
end
