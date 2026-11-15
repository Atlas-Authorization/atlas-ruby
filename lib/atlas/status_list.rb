# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require_relative "error"
require_relative "transport"
require_relative "jws"

module Atlas
  # The signed session status list: a compact, signed set of recently revoked session ids that an edge (a proxy,
  # a CDN worker) can check offline. Atlas serves it at +GET /v1/sessions/revocations/status-list+.
  module StatusList
    # A list that cannot be trusted. +reason+: +:malformed+, +:unsupported+, +:no_key+, +:bad_signature+,
    # +:bad_claims+, +:expired+.
    class InvalidError < Atlas::Error
      attr_reader :reason

      def initialize(reason)
        @reason = reason
        super("Invalid session status list: #{reason}")
      end
    end

    # A verified list. Times are epoch ms. {#has?} is a binary search over the sorted truncated sha256 hashes.
    Verified = Struct.new(:count, :truncated, :issued_at, :expires_at, :since, :hash_bytes, :list, keyword_init: true) do
      def has?(sid)
        needle = Digest::SHA256.digest(sid.to_s).byteslice(0, hash_bytes)
        lo = 0
        hi = count - 1
        while lo <= hi
          mid = (lo + hi) / 2
          c = list.byteslice(mid * hash_bytes, hash_bytes) <=> needle
          return true if c.zero?

          c.negative? ? lo = mid + 1 : hi = mid - 1
        end
        false
      end
    end

    ALGS = { "RS256" => "RSA", "PS256" => "RSA", "ES256" => "EC", "ES384" => "EC", "EdDSA" => "OKP" }.freeze
    CURVES = { "ES256" => "P-256", "ES384" => "P-384", "EdDSA" => "Ed25519" }.freeze

    module_function

    def b64u_decode(s)
      raise InvalidError, :malformed unless s.match?(/\A[A-Za-z0-9_-]*\z/)

      Base64.urlsafe_decode64(s + ("=" * ((4 - (s.length % 4)) % 4)))
    end

    def parse_json(bytes)
      v = JSON.parse(bytes)
      return v if v.is_a?(Hash)

      raise InvalidError, :malformed
    rescue JSON::ParserError
      raise InvalidError, :malformed
    end

    # Verify a status-list token (+typ+ +statuslist+jwt+).
    # @param jwks [Hash, #call] +{ "keys" => [...] }+, or a callable +(kid) -> Hash | nil+.
    # @param now [#call, nil] clock returning epoch milliseconds.
    # @return [Verified]
    # @raise [InvalidError]
    def verify_token(token, jwks:, issuer: nil, now: nil, skew_seconds: 30)
      parts = token.to_s.split(".", -1)
      raise InvalidError, :malformed if parts.length != 3 || token.length > 4_000_000

      header = parse_json(b64u_decode(parts[0]))
      raise InvalidError, :unsupported unless header["typ"] == "statuslist+jwt"

      alg = header["alg"]
      kty = ALGS[alg] or raise InvalidError, :unsupported
      kid = header["kid"].is_a?(String) ? header["kid"] : nil
      set = jwks.respond_to?(:call) ? jwks.call(kid) : jwks
      jwk = Array(set && set["keys"]).find do |k|
        (kid ? k["kid"] == kid : true) && k["kty"] == kty && (CURVES[alg].nil? || k["crv"] == CURVES[alg])
      end
      raise InvalidError, :no_key unless jwk

      valid = begin
        verify_signature(alg, jwk, "#{parts[0]}.#{parts[1]}", b64u_decode(parts[2]))
      rescue StandardError
        raise InvalidError, :bad_signature
      end
      raise InvalidError, :bad_signature unless valid

      claims = parse_json(b64u_decode(parts[1]))
      now_sec = (now ? now.call : (Time.now.to_f * 1000)) / 1000.0
      num = lambda do |v|
        raise InvalidError, :bad_claims unless v.is_a?(Numeric)

        v
      end
      raise InvalidError, :bad_claims if claims["aud"] != "atlas:session-status-list" || claims["token_use"] != "session_status_list"
      raise InvalidError, :bad_claims if issuer && claims["iss"] != issuer

      exp = num.call(claims["exp"])
      iat = num.call(claims["iat"])
      raise InvalidError, :expired if exp + skew_seconds < now_sec
      raise InvalidError, :bad_claims if iat - skew_seconds > now_sec

      hash_bytes = num.call(claims["hash_bytes"])
      raise InvalidError, :bad_claims unless hash_bytes.is_a?(Integer) && hash_bytes.between?(4, 32)

      count = num.call(claims["count"])
      list = claims["h"].is_a?(String) ? b64u_decode(claims["h"]) : nil
      raise InvalidError, :bad_claims if list.nil? || !count.is_a?(Integer) || list.bytesize != count * hash_bytes

      Verified.new(count: count, truncated: claims["truncated"] == true, issued_at: iat * 1000, expires_at: exp * 1000,
                   since: num.call(claims["since"]), hash_bytes: hash_bytes, list: list)
    end

    def verify_signature(alg, jwk, data, sig) = JWS.verify_signature(alg, jwk, data, sig)

    # Checks a session id against the signed status list, refreshed over the Backend API.
    #
    # +check(sid)+ answers +:revoked+, +:ok+ or +:unavailable+ (no list yet, a truncated list that does not name the sid,
    # or a list gone stale past +stale_after_ms+ (+serve_stale_for_ms+ grace) with +on_stale: :reject+).
    class EdgeChecker
      def initialize(secret_key:, jwks_url:, api_url: DEFAULT_API_URL, issuer: nil, window_seconds: nil, refresh_ms: 30_000,
                     stale_after_ms: 120_000, serve_stale_for_ms: 0, on_stale: :reject, http: nil, now: nil, on_error: nil,
                     on_serve_stale: nil)
        @transport = Transport.new(secret_key: secret_key, api_url: api_url, http: http)
        @http = http || NetHTTPRequester.new
        @jwks_url = jwks_url
        @issuer = issuer
        @window = window_seconds
        @refresh_ms = refresh_ms
        @stale_after_ms = stale_after_ms
        @serve_stale_for_ms = serve_stale_for_ms
        @on_stale = on_stale
        @now = now
        @on_error = on_error
        @on_serve_stale = on_serve_stale
        @current = nil
        @last_success_at = nil
        @jwks = nil
        @jwks_at = 0
        @mutex = Mutex.new
      end

      # Epoch ms of the last successful refresh, or nil.
      attr_reader :last_success_at

      def check(sid)
        @mutex.synchronize do
          refresh if @current.nil? || @last_success_at.nil? || clock - @last_success_at >= @refresh_ms
          stale = @last_success_at.nil? ? Float::INFINITY : clock - @last_success_at - @stale_after_ms
          return(@on_stale == :allow ? :ok : :unavailable) if @current.nil?
          return :revoked if @current.has?(sid)
          return :unavailable if @current.truncated
          if stale.positive? && @on_stale != :allow
            return :unavailable unless stale <= @serve_stale_for_ms

            @on_serve_stale&.call(last_success_at: @last_success_at, stale_for_ms: stale)
          end
          :ok
        end
      end

      private

      def clock = (@now ? @now.call : (Time.now.to_f * 1000)).to_i

      def keys(kid)
        stale = @jwks.nil? || clock - @jwks_at > 600_000 ||
                (kid && @jwks["keys"].none? { |k| k["kid"] == kid } && clock - @jwks_at > 60_000)
        if stale
          status, text, = @http.call("GET", @jwks_url, { "accept" => "application/json" }, nil)
          raise "JWKS answered #{status}" unless status.between?(200, 299)

          @jwks = JSON.parse(text)
          @jwks_at = clock
        end
        @jwks
      end

      def refresh
        query = @window ? { window_seconds: @window } : nil
        body = @transport.request(method: :get, path: "/v1/sessions/revocations/status-list", query: query)
        raise "status list answer had no token" unless body.is_a?(Hash) && body["token"].is_a?(String)

        @current = StatusList.verify_token(body["token"], jwks: method(:keys), issuer: @issuer, now: -> { clock })
        @last_success_at = clock
      rescue StandardError => e
        @on_error&.call(e)
      end
    end
  end
end
