# frozen_string_literal: true

require "json"
require "base64"
require "digest"
require "net/http"
require "uri"

module Atlas
  # RFC 7662 token introspection at Atlas, for opaque (reference) access tokens.
  #
  # An API, client or instance set to the +opaque+ access-token format gets
  # +oat_…+ tokens only Atlas can read. The introspector asks Atlas with your
  # API's own client credentials (client_secret_basic) and caches the answer by
  # the token's SHA-256 (the token itself is never kept). The client must be a
  # confidential client the API lists in +introspection_client_ids+ (or the
  # client the tokens are issued to).
  class Introspector
    # Atlas could not be reached, or answered with a non-2xx status.
    class Error < StandardError; end

    attr_reader :introspect_jwts

    # @param issuer [String] the instance issuer.
    # @param client_id [String], client_secret [String] your API's client.
    # @param endpoint [String, nil] default +issuer/oauth2/introspect+.
    # @param cache_ttl [Numeric] seconds an active answer is reused (default 60;
    #   never past the token's +exp+).
    # @param negative_cache_ttl [Numeric] seconds an inactive answer is reused
    #   (default 10; 0 disables).
    # @param cache_max [Integer] most answers kept (default 10 000).
    # @param introspect_jwts [Boolean] also send JWT access tokens to Atlas, so a
    #   revoked grant or a banned user is refused before the token expires.
    # @param post_impl [#call, nil] +(url, form, headers) -> [status, body]+ (tests).
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(issuer:, client_id:, client_secret:, endpoint: nil, cache_ttl: 60, negative_cache_ttl: 10,
                   cache_max: 10_000, introspect_jwts: false, post_impl: nil, now: nil)
      if client_id.to_s.empty? || client_secret.to_s.empty?
        raise ArgumentError, "introspection needs client_id and client_secret"
      end

      @endpoint = endpoint || "#{issuer.sub(%r{/+\z}, '')}/oauth2/introspect"
      @basic = "Basic #{Base64.strict_encode64("#{URI.encode_www_form_component(client_id)}:" \
                                                "#{URI.encode_www_form_component(client_secret)}")}"
      @ttl = cache_ttl
      @negative_ttl = negative_cache_ttl
      @max = cache_max
      @introspect_jwts = introspect_jwts
      @post_impl = post_impl
      @now = now
      @cache = {}
      @mutex = Mutex.new
    end

    def self.cache_key(token)
      Base64.urlsafe_encode64(Digest::SHA256.digest(token), padding: false)
    end

    # The claims of an active access token, or +nil+ for an inactive one (also
    # for a refresh token). Raises {Error} when Atlas could not be asked.
    def introspect(token)
      key = self.class.cache_key(token)
      now = now_seconds
      @mutex.synchronize do
        hit = @cache[key]
        if hit
          return hit[0] if hit[1] > now

          @cache.delete(key)
        end
      end

      status, raw = post({ "token" => token, "token_type_hint" => "access_token" })
      raise Error, "Introspection failed with HTTP #{status}." unless status.between?(200, 299)

      body = begin
        JSON.parse(raw.to_s)
      rescue JSON::ParserError
        raise Error, "Introspection answered with invalid JSON."
      end
      claims = body.is_a?(Hash) && body["active"] == true && body["token_use"] != "refresh_token" ? body : nil
      now = now_seconds
      until_at = if claims
                   exp = claims["exp"]
                   exp.is_a?(Numeric) ? [now + @ttl, exp.to_f].min : now + @ttl
                 else
                   now + @negative_ttl
                 end
      remember(key, claims, until_at, now) if until_at > now
      claims
    end

    private

    def remember(key, claims, until_at, now)
      @mutex.synchronize do
        @cache.delete(key)
        @cache[key] = [claims, until_at]
        if @cache.size > @max
          @cache.delete_if { |_, v| v[1] <= now }
          @cache.delete(@cache.keys.first) while @cache.size > @max
        end
      end
    end

    def now_seconds
      @now ? @now.call / 1000.0 : Time.now.to_f
    end

    def post(form)
      headers = { "Authorization" => @basic, "Accept" => "application/json",
                  "Content-Type" => "application/x-www-form-urlencoded" }
      return @post_impl.call(@endpoint, form, headers) if @post_impl

      uri = URI(@endpoint)
      req = Net::HTTP::Post.new(uri)
      headers.each { |k, v| req[k] = v }
      req.body = URI.encode_www_form(form)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 10,
                                                read_timeout: 10) { |http| http.request(req) }
      [res.code.to_i, res.body]
    rescue Error
      raise
    rescue StandardError => e
      raise Error, e.message
    end
  end
end
