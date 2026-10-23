# frozen_string_literal: true

require "uri"

module Atlas
  # Moving from Better Auth to Atlas without signing anyone out.
  #
  # During the migration window a returning user still carries their Better Auth
  # session cookie (+better-auth.session_token+, +__Secure-+ prefixed over
  # https). It is HttpOnly, so only your server can read it. The bridge reads it,
  # exchanges it ONCE with Atlas through the Backend API (secret key, forwarding
  # the end user's IP and user agent), sets the Atlas session as your own
  # first-party cookies and clears the Better Auth cookies. Atlas finds the
  # session in your import (or asks your old app, with the live fallback on) and
  # runs the normal sign-in path on it — MFA policy included.
  #
  #   use Atlas::BetterAuth::RackMiddleware, client: Atlas::Client.new(ENV["ATLAS_SECRET_KEY"]),
  #                                          sign_in_url: "https://app.example.com/sign-in"
  #
  # Rails: set +Atlas.configure { |c| c.better_auth_bridge = true }+ (with
  # +secret_key+) and {Atlas::Rails::Middleware} runs it.
  module BetterAuth
    # Better Auth's default cookie prefix (+advanced.cookiePrefix+).
    COOKIE_PREFIX = "better-auth"
    # The Backend API path of the secret-key exchange.
    EXCHANGE_PATH = "/v1/migrations/better_auth/exchange"
    # Refusal outcomes Atlas reports in +meta.bridge_outcome+.
    KNOWN_OUTCOMES = %w[closed invalid signature_invalid expired reused user_unavailable rate_limited].freeze
    # Refusals that say the session will never exchange: its cookies are cleared.
    FINAL_OUTCOMES = %w[invalid signature_invalid expired reused user_unavailable].freeze

    # The classified outcome of an exchange. +kind+ is +:session+ (+jwt+,
    # +refresh_token+, +session_id+, +user_id+, +expires_in+), +:needs_mfa+
    # (+attempt_id+, +status+: the Better Auth session is spent) or +:refused+
    # (+outcome+; +http_status+ 0 for a transport failure).
    ExchangeResult = Struct.new(:kind, :jwt, :refresh_token, :session_id, :user_id, :expires_in,
                                :attempt_id, :status, :outcome, :http_status, keyword_init: true)

    # A cookie to set (or, with +max_age: 0+, clear).
    Cookie = Struct.new(:name, :value, :path, :domain, :http_only, :same_site, :secure, :max_age,
                        keyword_init: true) do
      # The +Set-Cookie+ header value.
      def to_header
        parts = ["#{name}=#{value}", "Path=#{path || '/'}"]
        parts << "Domain=#{domain}" if domain
        unless max_age.nil?
          parts << "Max-Age=#{max_age}"
          parts << "Expires=Thu, 01 Jan 1970 00:00:00 GMT" if max_age.zero?
        end
        parts << "HttpOnly" if http_only
        parts << "Secure" if secure
        parts << "SameSite=#{same_site.to_s.capitalize}" if same_site
        parts.join("; ")
      end
    end

    # What the bridge decided for one request: +:none+, +:signed_in+ (set
    # +cookies+ and re-enter the same URL), +:needs_mfa+ (set +cookies+, redirect
    # to {#continuation_url}) or +:refused+ (set +cookies+ — they clear the Better
    # Auth cookies only on a final refusal — and carry on).
    Decision = Struct.new(:action, :cookies, :session, :attempt_id, :status, :outcome, keyword_init: true) do
      # +url+ with +__atlas_attempt+ / +__atlas_status+ set.
      def continuation_url(url)
        uri = URI.parse(url)
        query = URI.decode_www_form(uri.query.to_s).reject { |k, _| %w[__atlas_attempt __atlas_status].include?(k) }
        query += [["__atlas_attempt", attempt_id], ["__atlas_status", status]]
        uri.query = URI.encode_www_form(query)
        uri.to_s
      end
    end

    module_function

    # The session cookie names the bridge reads (the +__Secure-+ name first) and
    # every Better Auth cookie it clears.
    # @return [Hash{Symbol=>Array<String>}] +:session_token+ and +:all+.
    def cookie_names(prefix = COOKIE_PREFIX)
      base = %w[session_token session_data account_data dont_remember].map { |n| "#{prefix}.#{n}" }
      { session_token: ["__Secure-#{prefix}.session_token", "#{prefix}.session_token"],
        all: base.map { |n| "__Secure-#{n}" } + base }
    end

    # Parse a +Cookie+ header into a Hash (first occurrence wins).
    def parse_cookies(header)
      out = {}
      header.to_s.split(";").each do |part|
        key, sep, value = part.strip.partition("=")
        out[key] = value if !sep.empty? && !key.empty? && !out.key?(key)
      end
      out
    end

    # The raw Better Auth session cookie value (the +__Secure-+ name first), or
    # nil. +cookies+ is a +Cookie+ header or a parsed Hash.
    def read_session_cookie(cookies, cookie_prefix: COOKIE_PREFIX, cookie_name: nil)
      jar = cookies.is_a?(Hash) ? cookies : parse_cookies(cookies)
      names = cookie_name ? ["__Secure-#{cookie_name}", cookie_name] : cookie_names(cookie_prefix)[:session_token]
      names.each do |name|
        value = jar[name]
        return value if value && !value.empty?
      end
      nil
    end

    # Exchange a Better Auth session for an Atlas session through +client+ (an
    # {Atlas::Client} on the instance secret key). Never raises: anything that is
    # not a verdict on the session (a 5xx, a transport failure) is
    # +:refused+ / +"unavailable"+, so the caller keeps the cookie and retries.
    # @return [ExchangeResult]
    def exchange(client, token, client_ip: nil, user_agent: nil, remember: nil)
      data = client.better_auth_bridge.exchange(token, client_ip: client_ip, user_agent: user_agent, remember: remember)
      classify(data)
    rescue Atlas::APIError => e
      return ExchangeResult.new(kind: :refused, outcome: "rate_limited", http_status: 429) if e.status == 429

      meta = e.errors.first.is_a?(Hash) ? e.errors.first["meta"] : nil
      outcome = meta.is_a?(Hash) ? meta["bridge_outcome"] : nil
      outcome = "unavailable" unless KNOWN_OUTCOMES.include?(outcome)
      ExchangeResult.new(kind: :refused, outcome: outcome, http_status: e.status)
    rescue StandardError
      ExchangeResult.new(kind: :refused, outcome: "unavailable", http_status: 0)
    end

    def classify(data)
      if data.is_a?(Hash)
        if data["object"] == "session_tokens" && data["jwt"] && data["refresh_token"]
          return ExchangeResult.new(kind: :session, jwt: data["jwt"], refresh_token: data["refresh_token"],
                                    session_id: data["session_id"].to_s, user_id: data["user_id"].to_s,
                                    expires_in: data["expires_in"].to_i, http_status: 200)
        end
        if data["object"] == "sign_in_attempt" && data["id"] &&
           %w[needs_second_factor needs_mfa_enrollment].include?(data["status"])
          return ExchangeResult.new(kind: :needs_mfa, attempt_id: data["id"], status: data["status"], http_status: 200)
        end
      end
      ExchangeResult.new(kind: :refused, outcome: "unavailable", http_status: 200)
    end

    # The end user's IP from a Rack env: the first +X-Forwarded-For+ hop, then
    # +X-Real-IP+, then +REMOTE_ADDR+ (only as trustworthy as your proxy).
    def client_ip_from(env)
      forwarded = env["HTTP_X_FORWARDED_FOR"].to_s.split(",").first.to_s.strip
      return forwarded unless forwarded.empty?

      real = env["HTTP_X_REAL_IP"].to_s.strip
      return real unless real.empty?

      env["REMOTE_ADDR"]
    end

    # The framework-neutral bridge. Call it with a request's cookies; it does
    # nothing (no network) without a Better Auth cookie or with an Atlas session
    # (+__session+ / +__atlas_rt+) present.
    class Bridge
      # @param client [Atlas::Client] on the instance secret key.
      # @param cookie_prefix [String] Better Auth's +advanced.cookiePrefix+.
      # @param cookie_name [String, nil] the session cookie's full name, when overridden.
      # @param better_auth_cookie_domain [String, nil] the domain the Better Auth
      #   cookies were set on, so they clear.
      # @param secure [Boolean] mark the Atlas cookies Secure (false only for local http).
      def initialize(client:, cookie_prefix: COOKIE_PREFIX, cookie_name: nil, better_auth_cookie_domain: nil,
                     secure: true)
        raise ConfigurationError, "Atlas::BetterAuth::Bridge needs client: (an Atlas::Client on the secret key)." if client.nil?

        @client = client
        @cookie_prefix = cookie_prefix || COOKIE_PREFIX
        @cookie_name = cookie_name
        @domain = better_auth_cookie_domain
        @secure = secure != false
      end

      # @param cookies [String, Hash] the +Cookie+ header or a parsed Hash.
      # @return [Decision]
      def call(cookies, client_ip: nil, user_agent: nil)
        jar = cookies.is_a?(Hash) ? cookies : BetterAuth.parse_cookies(cookies)
        token = BetterAuth.read_session_cookie(jar, cookie_prefix: @cookie_prefix, cookie_name: @cookie_name)
        return Decision.new(action: :none, cookies: []) if token.nil?
        # Already on Atlas: leave the old cookie for the old app's own expiry.
        return Decision.new(action: :none, cookies: []) if present?(jar["__session"]) || present?(jar["__atlas_rt"])

        decide(BetterAuth.exchange(@client, token, client_ip: client_ip, user_agent: user_agent))
      end

      private

      def present?(value) = value && !value.empty?

      def clear
        names = BetterAuth.cookie_names(@cookie_prefix)[:all]
        names += [@cookie_name, "__Secure-#{@cookie_name}"] if @cookie_name
        # A __Secure- cookie can only be overwritten by a Secure Set-Cookie.
        names.map { |n| Cookie.new(name: n, value: "", path: "/", domain: @domain, max_age: 0, secure: n.start_with?("__Secure-")) }
      end

      def decide(result)
        case result.kind
        when :session
          Decision.new(action: :signed_in, session: result, cookies: [
            Cookie.new(name: "__session", value: result.jwt, path: "/", same_site: :lax, secure: @secure),
            Cookie.new(name: "__atlas_rt", value: result.refresh_token, path: "/", http_only: true, same_site: :lax,
                       secure: @secure),
            *clear
          ])
        when :needs_mfa
          Decision.new(action: :needs_mfa, attempt_id: result.attempt_id, status: result.status, cookies: clear)
        else
          Decision.new(action: :refused, outcome: result.outcome,
                       cookies: FINAL_OUTCOMES.include?(result.outcome) ? clear : [])
        end
      end
    end

    # Rack middleware: a GET/HEAD carrying a Better Auth session cookie and no
    # Atlas session is exchanged once and redirected (302) to the same URL with
    # the Atlas cookies set and the Better Auth cookies cleared; a user who owes
    # a second factor goes to +sign_in_url+ with +__atlas_attempt+ /
    # +__atlas_status+. Everything else passes through.
    class RackMiddleware
      # @param app [#call] the next Rack app.
      # @param bridge [Bridge, nil] a prepared bridge; otherwise built from +client:+ and the options.
      # @param sign_in_url [String, nil] where a second factor is finished (default the requested URL).
      def initialize(app, bridge: nil, sign_in_url: nil, **bridge_options)
        @app = app
        @bridge = bridge || Bridge.new(**bridge_options)
        @sign_in_url = sign_in_url
      end

      def call(env)
        BetterAuth.handle(@bridge, env, sign_in_url: @sign_in_url) { @app.call(env) }
      end
    end

    # Run +bridge+ for a Rack +env+; yields to the app unless it answers with a
    # redirect, and appends any cookies to the app's response.
    # @return [Array] a Rack response.
    def handle(bridge, env, sign_in_url: nil)
      return yield unless %w[GET HEAD].include?(env["REQUEST_METHOD"])

      decision = bridge.call(env["HTTP_COOKIE"].to_s, client_ip: client_ip_from(env), user_agent: env["HTTP_USER_AGENT"])
      case decision.action
      when :signed_in, :needs_mfa
        target = if decision.action == :signed_in
                   path = env["SCRIPT_NAME"].to_s + env["PATH_INFO"].to_s
                   env["QUERY_STRING"].to_s.empty? ? path : "#{path}?#{env['QUERY_STRING']}"
                 else
                   decision.continuation_url(sign_in_url || request_url(env))
                 end
        [302, { "location" => target, "set-cookie" => set_cookie_value(decision.cookies.map(&:to_header)) }, []]
      else
        status, headers, body = yield
        unless decision.cookies.empty?
          headers = headers.dup
          existing = headers.delete("Set-Cookie") || headers["set-cookie"]
          existing = existing.is_a?(Array) ? existing : existing.to_s.split("\n")
          headers["set-cookie"] = set_cookie_value(existing + decision.cookies.map(&:to_header))
        end
        [status, headers, body]
      end
    end

    # Rack 3 takes an Array of Set-Cookie values; Rack 2 a newline-joined String.
    def set_cookie_value(values)
      rack3 = defined?(::Rack::RELEASE) && ::Rack::RELEASE.to_s.split(".").first.to_i >= 3
      rack3 ? values : values.join("\n")
    end

    def request_url(env)
      scheme = env["HTTP_X_FORWARDED_PROTO"] || env["rack.url_scheme"] || "http"
      host = env["HTTP_X_FORWARDED_HOST"] || env["HTTP_HOST"] || env["SERVER_NAME"]
      path = env["SCRIPT_NAME"].to_s + env["PATH_INFO"].to_s
      query = env["QUERY_STRING"].to_s
      "#{scheme}://#{host}#{path}#{query.empty? ? '' : "?#{query}"}"
    end
  end
end
