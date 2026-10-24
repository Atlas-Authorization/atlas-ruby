# frozen_string_literal: true

require_relative "error"
require_relative "jwks_cache"
require_relative "verifier"

module Atlas
  # Raised by {Atlas::BackchannelLogout#verify} for any logout token that must
  # be refused. Answer the request with 400, or with 503 and +Retry-After+ when
  # {#retryable?} is true (Atlas then retries the delivery; it never retries a 400).
  class InvalidLogoutTokenError < Error
    # @return [Symbol] a coarse reason (+:malformed+, +:invalid_signature+,
    #   +:wrong_type+, +:missing_claim+, +:nonce_present+, +:replayed+, ...).
    attr_reader :reason

    def initialize(reason, message = nil)
      @reason = reason
      super(message || "Invalid logout token (#{reason}).")
    end

    # True when the failure is temporary and on your side: +:no_keys+, the
    # issuer's keys could not be fetched (a network error or a JWKS outage).
    # @return [Boolean]
    def retryable?
      reason == :no_keys
    end
  end

  # The verified claims of a back-channel logout token. End the local
  # session(s) matching +sid+ (one session) or, when +sid+ is nil, every
  # session of +sub+.
  LogoutTokenClaims = Struct.new(:sub, :sid, :jti, :iat, :claims, keyword_init: true)

  # A tiny thread-safe in-memory replay guard for logout token +jti+s. Fine for
  # a single process; with several processes, back +BackchannelLogout+ with a
  # shared store (Redis +SET NX EX+, a unique DB column) exposing the same
  # +add?(jti, ttl_seconds)+ method.
  class MemoryJtiStore
    def initialize(now: nil)
      @seen = {}
      @now = now
      @mutex = Mutex.new
    end

    # Record +jti+ for +ttl_seconds+. Returns true the first time, false on a replay.
    def add?(jti, ttl_seconds)
      @mutex.synchronize do
        t = current_time
        @seen.delete_if { |_, expires| expires <= t } if @seen.size > 1000
        expires = @seen[jti]
        return false if expires && expires > t

        @seen[jti] = t + ttl_seconds
        true
      end
    end

    private

    def current_time
      @now ? @now.call : Time.now.to_i
    end
  end

  # Verify an OpenID Connect Back-Channel Logout token (OIDC Back-Channel
  # Logout 1.0, section 2.6) — the +logout_token+ Atlas POSTs to an app's
  # +backchannel_logout_uri+ when a user signs out.
  #
  # Checks: RS256 signature against the issuer's JWKS, +iss+, +aud+ contains
  # your +client_id+, +iat+ present and not in the future, +exp+ (when present)
  # not passed, +jti+ present, +events+ carries the back-channel logout event
  # with an object value, +sid+ and/or +sub+ present, no +nonce+, and a +typ+
  # header (when present) of +logout+jwt+.
  #
  #   logout = Atlas::BackchannelLogout.new(
  #     issuer: "https://atlasauth.net",                       # or your instance's frontend API origin
  #     jwks_url: "https://atlasauth.net/.well-known/jwks.json",
  #     client_id: ENV.fetch("ATLAS_CLIENT_ID"),
  #     jti_store: Atlas::MemoryJtiStore.new                   # optional replay protection
  #   )
  #   begin
  #     claims = logout.verify(params[:logout_token])
  #   rescue Atlas::InvalidLogoutTokenError => e
  #     # 503 + Retry-After makes Atlas retry (keys unreachable); 400 is final.
  #     e.retryable? ? head(:service_unavailable, "Retry-After" => "30") : head(:bad_request)
  #   end
  class BackchannelLogout
    EVENT = "http://schemas.openid.net/event/backchannel-logout"
    # How far in the future an +iat+ may be (clock skew), and how old a token
    # without +exp+ may be.
    DEFAULT_LEEWAY_SECONDS = 60
    DEFAULT_MAX_AGE_SECONDS = 600

    # @param issuer [String] the expected +iss+.
    # @param jwks_url [String] where the issuer's signing keys are published.
    # @param client_id [String] your app's client id (the token's +aud+).
    # @param jti_store [#add?, nil] optional replay guard (see {MemoryJtiStore}).
    # @param leeway [Integer] allowed clock skew, seconds.
    # @param max_age [Integer] reject a token whose +iat+ is older than this
    #   when it carries no +exp+.
    # @param fetch_impl [#call, nil] injectable JWKS fetcher (tests).
    # @param now [#call, nil] clock returning epoch seconds (tests).
    def initialize(issuer:, jwks_url:, client_id:, jti_store: nil, leeway: DEFAULT_LEEWAY_SECONDS,
                   max_age: DEFAULT_MAX_AGE_SECONDS, fetch_impl: nil, now: nil)
      begin
        require "jwt"
      rescue LoadError
        raise Atlas::Error, "Logout token verification needs the `jwt` gem. Add `gem \"jwt\"` to your Gemfile."
      end
      @issuer = issuer
      @client_id = client_id
      @jti_store = jti_store
      @leeway = leeway
      @max_age = max_age
      @now = now
      jwks_now = now && -> { now.call * 1000 }
      @jwks = JwksCache.new(url: jwks_url, fetch_impl: fetch_impl, now: jwks_now)
    end

    # @return [Atlas::LogoutTokenClaims]
    # @raise [Atlas::InvalidLogoutTokenError]
    def verify(logout_token)
      token = logout_token.to_s
      fail!(:malformed) if token.split(".").length != 3

      kid = Atlas.read_kid(token)
      keys = @jwks.get(kid)
      fail!(:no_keys) if keys.nil? || keys["keys"].nil? || keys["keys"].empty?
      # A key Atlas just rotated to, whose refetch failed: temporary.
      fail!(:no_keys) if kid && @jwks.last_outcome == :failed && keys["keys"].none? { |k| k["kid"] == kid }

      payload, header = decode(token, keys)
      check_header(header)
      check_claims(payload)

      jti = payload["jti"]
      if @jti_store
        ttl = payload["exp"].is_a?(Numeric) ? [payload["exp"].to_i - current_time, 0].max + @leeway : @max_age + @leeway
        fail!(:replayed) unless @jti_store.add?(jti, ttl)
      end

      LogoutTokenClaims.new(sub: payload["sub"], sid: payload["sid"], jti: jti, iat: payload["iat"], claims: payload)
    end

    private

    def decode(token, keys)
      JWT.decode(
        token, nil, true,
        algorithms: SIGNING_ALGS,
        jwks: JWT::JWK::Set.new(keys),
        iss: @issuer, verify_iss: true,
        aud: @client_id, verify_aud: true,
        verify_expiration: false, verify_not_before: false, verify_iat: false
      )
    rescue JWT::InvalidIssuerError
      fail!(:wrong_issuer)
    rescue JWT::InvalidAudError
      fail!(:wrong_audience)
    rescue JWT::DecodeError, StandardError
      fail!(:invalid_signature)
    end

    def check_header(header)
      fail!(:wrong_algorithm) unless SIGNING_ALGS.include?(header["alg"])
      typ = header["typ"]
      return if typ.nil?

      fail!(:wrong_type) unless %w[logout+jwt application/logout+jwt].include?(typ.to_s.downcase)
    end

    def check_claims(payload)
      now = current_time
      iat = payload["iat"]
      fail!(:missing_claim, "Logout token has no iat.") unless iat.is_a?(Numeric)
      fail!(:issued_in_future) if iat > now + @leeway

      exp = payload["exp"]
      if exp.nil?
        fail!(:expired) if iat < now - @max_age - @leeway
      else
        fail!(:invalid_claim, "Logout token exp is not a number.") unless exp.is_a?(Numeric)
        fail!(:expired) if exp < now - @leeway
      end

      jti = payload["jti"]
      fail!(:missing_claim, "Logout token has no jti.") unless jti.is_a?(String) && !jti.empty?

      events = payload["events"]
      fail!(:missing_claim, "Logout token has no back-channel logout event.") unless events.is_a?(Hash) && events.key?(EVENT)
      fail!(:invalid_claim, "Logout token event value must be an object.") unless events[EVENT].is_a?(Hash)

      sub = payload["sub"]
      sid = payload["sid"]
      fail!(:missing_claim, "Logout token has neither sub nor sid.") unless present?(sub) || present?(sid)
      fail!(:nonce_present) if payload.key?("nonce")
    end

    def present?(value)
      value.is_a?(String) && !value.empty?
    end

    def current_time
      @now ? @now.call : Time.now.to_i
    end

    def fail!(reason, message = nil)
      raise InvalidLogoutTokenError.new(reason, message)
    end
  end

  # A Rack endpoint for the back-channel logout URL (Sinatra, Hanami, Roda, Rails
  # routes: +mount Atlas::BackchannelLogoutApp.new(...), at: "/atlas/logout"+).
  # It reads the +logout_token+ form field, verifies it with {BackchannelLogout}
  # and calls your block with the {LogoutTokenClaims}; the answer follows the
  # spec: 200 on success, 400 for a final refusal, 503 + +Retry-After+ when the
  # issuer's keys are unreachable (Atlas retries).
  #
  #   run Atlas::BackchannelLogoutApp.new(logout: verifier) { |claims| Sessions.revoke(sid: claims.sid, sub: claims.sub) }
  class BackchannelLogoutApp
    def initialize(logout:, retry_after: 30, &on_logout)
      raise ArgumentError, "BackchannelLogoutApp needs an on_logout block" unless on_logout

      @logout = logout
      @retry_after = retry_after
      @on_logout = on_logout
    end

    def call(env)
      return respond(405, "method not allowed", "Allow" => "POST") unless env["REQUEST_METHOD"] == "POST"

      form = URI.decode_www_form(env["rack.input"].read.to_s).to_h
      env["rack.input"].rewind if env["rack.input"].respond_to?(:rewind)
      claims = @logout.verify(form["logout_token"])
      @on_logout.call(claims)
      respond(200, "")
    rescue InvalidLogoutTokenError => e
      if e.retryable?
        respond(503, "keys unavailable", "Retry-After" => @retry_after.to_s)
      else
        respond(400, "invalid logout token")
      end
    end

    private

    def respond(status, body, extra = {})
      [status, { "content-type" => "text/plain", "cache-control" => "no-store" }.merge(extra), [body]]
    end
  end
end
