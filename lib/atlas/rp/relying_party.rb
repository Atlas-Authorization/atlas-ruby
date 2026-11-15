# frozen_string_literal: true

require "base64"
require "json"
require "time"
require "uri"

require_relative "../error"
require_relative "../transport"
require_relative "../backchannel_logout"
require_relative "http"
require_relative "oidc_flow"
require_relative "sid_store"

module Atlas
  # Who signed in: the ID-token claims an app needs, in the token's own names.
  RPUser = Struct.new(:sub, :sid, :email, :email_verified, :name, :external_id, :org_id, :org_role, :auth_time, keyword_init: true)
  # The tokens of one sign-in. +expires_at+ is epoch milliseconds.
  RPTokens = Struct.new(:id_token, :access_token, :refresh_token, :expires_at, keyword_init: true)
  # The outcome of a finished sign-in. +response+ is a 302 to the return path that already clears the
  # sign-in cookie; append your own session cookie to it (+response.add_cookie+).
  RPCallbackResult = Struct.new(:user, :tokens, :identity, :response, keyword_init: true)

  # The server-side relying party for Atlas's hosted sign-in (the redirect flow): send the user to the
  # hosted page, verify who came back, keep your own session.
  #
  #   rp = Atlas::RelyingParty.new(
  #     issuer: ENV["ATLAS_ISSUER"], client_id: ENV["ATLAS_CLIENT_ID"], client_secret: ENV["ATLAS_CLIENT_SECRET"],
  #     redirect_uri: "https://app.example.com/auth/callback", secret: ENV["SESSION_SECRET"],
  #     secret_key: ENV["ATLAS_SECRET_KEY"]
  #   )
  #   response = rp.handle(Atlas::RP::Request.from_rack(env), on_signed_in: ->(user, tokens, request, result) { ... })
  #
  # Most apps use {Atlas::RP::Middleware} (Rack, Rails, Sinatra), which wires this up with a sealed
  # session cookie. With a +secret_key+ the Atlas session is kept alive and revoked through the
  # Backend API; a Sign in with Atlas app (issuer +https://atlasauth.net+) has none and uses its client
  # credentials instead.
  class RelyingParty
    DEFAULT_TOUCH_INTERVAL = 300
    CONFIRM_NOW_WINDOW_SECONDS = 60
    NOT_FORWARDABLE = %w[response_type client_id redirect_uri state nonce code_challenge code_challenge_method scope
                         return_to id_token_hint request request_uri].freeze
    MAX_FORWARDED_VALUE = 512
    PASSTHROUGH = { "prompt" => :prompt, "login_hint" => :login_hint, "ui_locales" => :ui_locales,
                    "organization" => :organization, "return_to" => :return_to }.freeze

    attr_reader :flow

    # @param secret [String] at least 32 characters; seals the short-lived sign-in cookie.
    # @param secret_key [String, nil] instance secret key (+sessions:write+) for server-side touch / revoke.
    # @param server_sign_out [Boolean] sign out with the one-call +POST /v1/oauth_clients/{id}/logout+.
    # @param forward_params [Array<String>] query parameters passed from your sign-in URL to +/oauth2/authorize+.
    # @param routes [Hash] +sign_in:+, +callback:+, +sign_out:+, +backchannel_logout:+ paths.
    # @param sid_store [#bind, #take, nil] see {Atlas::MemorySidStore}.
    # @param on_signed_in [#call] +(user, tokens, request, result)+; return a {Atlas::RP::Response} or nothing.
    # @param on_sign_in_error [#call] +(error, request)+, return a {Atlas::RP::Response}.
    # @param on_sign_out [#call] +(request)+, return a Hash with +:sid+, +:id_token+, +:set_cookies+ (or nil).
    # @param on_backchannel_logout [#call] +(app_session_ids, claims)+; raising answers 503 so Atlas retries.
    # @param http [#call, nil] injectable requester (the Transport +http:+ seam).
    # @param now [#call, nil] clock returning a Time or epoch seconds, for tests.
    def initialize(issuer:, client_id:, redirect_uri:, secret:, client_secret: nil, client_auth: nil, scope: nil,
                   after_sign_in_path: "/", post_logout_redirect_uri: nil, secret_key: nil, api_url: nil,
                   cookie_name: nil, server_sign_out: false, touch_interval: DEFAULT_TOUCH_INTERVAL, forward_params: [],
                   routes: {}, sid_store: nil, on_signed_in: nil, on_sign_in_error: nil, on_sign_out: nil,
                   on_backchannel_logout: nil, http: nil, now: nil)
      raise ArgumentError, "RelyingParty: `after_sign_in_path` must be a path starting with a single `/`." unless OIDC::Flow.safe_return_to?(after_sign_in_path)

      forward_params.each do |name|
        unless name.is_a?(String) && name.match?(/\A[A-Za-z0-9_.-]{1,64}\z/) && !NOT_FORWARDABLE.include?(name)
          raise ArgumentError, "RelyingParty: `forward_params` cannot forward #{name.inspect}: use a plain parameter name the helper does not set itself."
        end
      end
      @config = { issuer: issuer.to_s.sub(%r{/+\z}, ""), client_id: client_id, client_secret: client_secret,
                  client_auth: client_auth, redirect_uri: redirect_uri, scope: scope,
                  after_sign_in_path: after_sign_in_path, post_logout_redirect_uri: post_logout_redirect_uri,
                  secret_key: secret_key, api_url: api_url || Atlas::DEFAULT_API_URL, server_sign_out: server_sign_out,
                  touch_interval: touch_interval, forward_params: forward_params, routes: routes }
      @sid_store = sid_store
      @on_signed_in = on_signed_in
      @on_sign_in_error = on_sign_in_error
      @on_sign_out = on_sign_out
      @on_backchannel_logout = on_backchannel_logout
      @http = http || NetHTTPRequester.new
      @now = now
      flow_opts = { issuer: issuer, client_id: client_id, redirect_uri: redirect_uri, secret: secret,
                    client_secret: client_secret, client_auth: client_auth, http: @http,
                    now: now && -> { clock_seconds } }
      flow_opts[:cookie_name] = cookie_name if cookie_name
      @flow = OIDC::Flow.new(**flow_opts)
      @transport = secret_key && Atlas::Transport.new(secret_key: secret_key, api_url: @config[:api_url], http: @http)
      @backchannel = nil
    end

    # Begin sign-in: a 302 to +/oauth2/authorize+ with the sign-in cookie set. +prompt+, +login_hint+,
    # +ui_locales+, +max_age+, +organization+ and +return_to+ on the request's query are passed through,
    # as are the +forward_params+ you configured; keyword +overrides+ win.
    # @return [Atlas::RP::Response]
    def start(request, **overrides)
      query = request.query
      from_query = {}
      PASSTHROUGH.each do |param, key|
        v = query[param]
        from_query[key] = v if v && !v.empty? && (key != :return_to || OIDC::Flow.safe_return_to?(v))
      end
      from_query[:max_age] = Integer(query["max_age"], 10) if query["max_age"]&.match?(/\A\d{1,9}\z/)
      forwarded = {}
      @config[:forward_params].each do |name|
        v = query[name]
        forwarded[name] = v if v && !v.empty? && v.length <= MAX_FORWARDED_VALUE
      end
      extra = forwarded.merge((overrides.delete(:extra_params) || {}).transform_keys(&:to_s))
      started = @flow.start(**{ scope: @config[:scope] }.merge(from_query).merge(overrides), extra_params: extra)
      RP::Response.redirect(started[:url], [started[:cookie]])
    end

    # Finish sign-in. Raises {Atlas::OIDC::Error} on any failure (send its +clear_cookie+ with your answer).
    # @return [Atlas::RPCallbackResult]
    def callback(request)
      identity = @flow.callback(query: request.query, cookie: request.cookie_header)
      claims = identity.claims
      user = RPUser.new(
        sub: identity.sub, sid: identity.sid, email: identity.email, email_verified: identity.email_verified,
        name: identity.name,
        external_id: claims["external_id"].is_a?(String) && !claims["external_id"].empty? ? claims["external_id"] : nil,
        org_id: identity.organization&.dig(:id), org_role: identity.organization&.dig(:role), auth_time: identity.auth_time
      )
      tokens = RPTokens.new(id_token: identity.id_token, access_token: identity.access_token,
                            refresh_token: identity.refresh_token, expires_at: identity.expires_at)
      RPCallbackResult.new(user: user, tokens: tokens, identity: identity,
                           response: RP::Response.redirect(identity.return_to || @config[:after_sign_in_path], [identity.clear_cookie]))
    end

    # Step-up: nil when +auth_time+ is within +max_age_seconds+; otherwise a 302 asking the same user to
    # authenticate again (+max_age+, plus +prompt=login+ for 0). The callback then refuses another user or
    # an old +auth_time+; store the new +user.auth_time+. +0+ asks unless the user authenticated in the last
    # {CONFIRM_NOW_WINDOW_SECONDS} seconds, so the request that returns from the confirmation goes through.
    # @return [Atlas::RP::Response, nil]
    def require_recent_auth(request, max_age_seconds, sub:, auth_time:, return_to: nil)
      unless max_age_seconds.is_a?(Integer) && max_age_seconds >= 0
        raise ArgumentError, "require_recent_auth: `max_age_seconds` must be a whole number of seconds, 0 or more."
      end
      raise ArgumentError, "require_recent_auth: `sub` is required." if sub.to_s.empty?

      allowed = max_age_seconds.zero? ? CONFIRM_NOW_WINDOW_SECONDS : max_age_seconds
      return nil if auth_time.is_a?(Numeric) && clock_seconds - auth_time <= allowed

      target = return_to || request.path_and_query
      opts = { scope: @config[:scope], max_age: max_age_seconds, expected_sub: sub }
      opts[:prompt] = "login" if max_age_seconds.zero?
      opts[:return_to] = target if OIDC::Flow.safe_return_to?(target)
      started = @flow.start(**opts)
      RP::Response.redirect(started[:url], [started[:cookie]])
    end

    # Keep the Atlas session alive while the user is active, at most once per +touch_interval+ per session.
    # Call it on each authenticated request with the +sid+ and when you last touched (nil at first).
    # With a +secret_key+ it touches the Atlas session; without one but with a +client_secret+ it touches
    # this app's own sign-in (a sid with no live sign-in of this app is +:ended+ / +:not_found+).
    # @return [Hash] +{ status: :skipped | :touched | :ended, ... }+
    def touch_if_due(sid, last_touched_at)
      now = clock_seconds
      if last_touched_at.is_a?(Numeric) && now - last_touched_at < @config[:touch_interval] && now >= last_touched_at
        return { status: :skipped, last_touched_at: last_touched_at }
      end

      if @transport.nil?
        status, body = app_session_call(sid, "touch", "touch_if_due")
        return { status: :touched, last_touched_at: now, idle_expires_at: idle_time(body && body["idle_expires_at"]) } if status.between?(200, 299)
        return { status: :ended, reason: :not_found } if status == 404 && body && body["error"] == "session_not_found"

        raise oauth_failure(status, body)
      end

      begin
        body = @transport.request(method: :post, path: "/v1/sessions/#{enc(sid)}/touch")
        { status: :touched, last_touched_at: now, idle_expires_at: body.is_a?(Hash) && body["idle_expires_at"].is_a?(String) ? body["idle_expires_at"] : nil }
      rescue Atlas::APIError => e
        return { status: :ended, reason: :not_found } if e.status == 404
        return { status: :ended, reason: ended_reason(e.code) } if e.status == 409

        raise # a key, scope or availability problem is not "signed out": say so loudly
      end
    end

    # End the Atlas session server-side; every app signed in through it gets a back-channel logout.
    # @return [Symbol] +:revoked+ or +:not_found+
    def revoke_session(sid)
      raise ArgumentError, "revoke_session: `secret_key` is not configured." unless @transport
      raise ArgumentError, "A session id (`sid`) is required." if sid.to_s.empty?

      @transport.request(method: :post, path: "/v1/sessions/#{enc(sid)}/revoke")
      :revoked
    rescue Atlas::APIError => e
      raise unless e.status == 404

      :not_found
    end

    # End THIS app's sign-in under +sid+ with the app's client credentials: its refresh grants are revoked and
    # Atlas sends the app a back-channel logout. The Atlas session and other apps are untouched.
    # @return [Symbol] +:ended+ or +:not_found+
    def end_app_session(sid)
      status, body = app_session_call(sid, "end", "end_app_session")
      return :ended if status.between?(200, 299)
      return :not_found if status == 404 && body && body["error"] == "session_not_found"

      raise oauth_failure(status, body)
    end

    # Record that your app session +app_session_id+ is backed by the Atlas +sid+ until +expires_at+ (epoch
    # seconds or Time), so a back-channel logout can end it. Needs +sid_store+.
    def bind_session(sid, app_session_id, expires_at)
      raise ArgumentError, "bind_session: `sid_store` is not configured." unless @sid_store
      raise ArgumentError, "bind_session: `sid` and `app_session_id` are required." if sid.to_s.empty? || app_session_id.to_s.empty?

      @sid_store.bind(sid, app_session_id, expires_at)
    end

    # The back-channel logout receiver: verifies the +logout_token+, takes the app sessions bound to its +sid+
    # from +sid_store+ and passes them to +on_backchannel_logout+. 200 when handled (or a replay), 400 for a bad
    # token, 503 (with +Retry-After+) when the keys could not be loaded or the callback raised.
    # @return [Atlas::RP::Response]
    def backchannel_logout(request)
      raise ArgumentError, "backchannel_logout: `on_backchannel_logout` is not configured." unless @on_backchannel_logout

      verifier = (@backchannel ||= Atlas::BackchannelLogout.new(
        issuer: @config[:issuer], jwks_url: @flow.discover["jwks_uri"], client_id: @config[:client_id],
        jti_store: Atlas::MemoryJtiStore.new,
        fetch_impl: lambda { |url|
          status, text, = @http.call("GET", url, { "accept" => "application/json" }, nil)
          [status, text]
        }
      ))
      claims = verifier.verify(request.form["logout_token"])
      ids = claims.sid && @sid_store ? Array(@sid_store.take(claims.sid)) : []
      begin
        @on_backchannel_logout.call(ids, claims)
      rescue StandardError
        # Put the bindings back so Atlas's retry finds them.
        ids.each { |id| @sid_store.bind(claims.sid, id, clock_seconds + 86_400) }
        return RP::Response.text(503, "Try again.", "retry-after" => "30")
      end
      RP::Response.text(200, "")
    rescue Atlas::InvalidLogoutTokenError => e
      e.retryable? ? RP::Response.text(503, "Try again.", "retry-after" => "30") : RP::Response.text(400, "Invalid logout token.")
    rescue Atlas::OIDC::Error
      RP::Response.text(503, "Try again.", "retry-after" => "30")
    end

    # Sign out: with a +sid+ and a +secret_key+, revokes the Atlas session server-side first, then 302s to
    # +/oauth2/logout+. With +server_sign_out+, one call ends this app's grants and the Atlas session and the 302
    # goes straight to the post-logout URI. End your own session (clear your cookie on this response) as well.
    # @return [Atlas::RP::Response]
    def sign_out(sid: nil, id_token: nil, post_logout_redirect_uri: nil, state: nil, set_cookies: [])
      target = post_logout_redirect_uri || @config[:post_logout_redirect_uri]
      if @config[:server_sign_out] && sid && @transport
        begin
          @transport.request(method: :post, path: "/v1/oauth_clients/#{enc(@config[:client_id])}/logout", body: { sid: sid })
        rescue Atlas::APIError => e
          raise unless e.status == 404 # no such session any more: nothing left to end
        end
        uri = URI.parse(target || "/")
        uri.query = URI.encode_www_form(URI.decode_www_form(uri.query.to_s) + [["state", state]]) if state
        return RP::Response.redirect(uri.to_s, set_cookies)
      end
      revoke_session(sid) if sid && @transport
      RP::Response.redirect(@flow.logout_url(post_logout_redirect_uri: target, id_token_hint: id_token, state: state), set_cookies)
    end

    # All the routes in one call: +GET+ on the sign-in path runs {#start}, +GET+ on the callback path runs
    # {#callback} then +on_signed_in+, +POST+ or +GET+ on the sign-out path runs +on_sign_out+ then {#sign_out},
    # and with +routes[:backchannel_logout]+ set, +POST+ there runs {#backchannel_logout}. Anything else is nil.
    # @return [Atlas::RP::Response, nil]
    def handle(request, on_signed_in: @on_signed_in, on_sign_in_error: @on_sign_in_error, on_sign_out: @on_sign_out)
      raise ArgumentError, "handle: `on_signed_in` is not configured; it is where your app creates its session." unless on_signed_in

      path = request.path
      verb = request.method
      routes = @config[:routes]
      return backchannel_logout(request) if verb == "POST" && routes[:backchannel_logout] && path == routes[:backchannel_logout]
      return start(request) if verb == "GET" && path == (routes[:sign_in] || "/auth/sign-in")

      if verb == "GET" && path == (routes[:callback] || URI.parse(@config[:redirect_uri]).path)
        begin
          result = callback(request)
        rescue Atlas::OIDC::Error => e
          failed = on_sign_in_error ? on_sign_in_error.call(e, request) : RP::Response.text(400, "Sign-in failed. Please try again.")
          return failed.add_cookie(e.clear_cookie)
        end
        own = on_signed_in.call(result.user, result.tokens, request, result)
        return own.is_a?(RP::Response) ? own.add_cookie(result.identity.clear_cookie) : result.response
      end

      if %w[POST GET].include?(verb) && path == (routes[:sign_out] || "/auth/sign-out")
        opts = (on_sign_out&.call(request) || {}).transform_keys(&:to_sym)
        return sign_out(**opts.slice(:sid, :id_token, :post_logout_redirect_uri, :state, :set_cookies))
      end
      nil
    end

    private

    def clock_seconds
      t = @now ? @now.call : Time.now
      t.to_i
    end

    def enc(segment) = URI.encode_www_form_component(segment.to_s)

    def ended_reason(code)
      { "SESSION_REVOKED" => :revoked, "SESSION_IDLE_EXPIRED" => :idle_expired }.fetch(code.to_s, :expired)
    end

    def idle_time(value)
      case value
      when Numeric then Time.at(value / 1000.0).utc.iso8601(3)
      when String then value
      end
    end

    # The app's own sign-in, authenticated like the token endpoint (+/oauth2/session/touch+ or +/end+).
    def app_session_call(sid, action, caller_name)
      method = @flow.client_auth
      secret = @config[:client_secret]
      if method == :none || secret.nil? || secret.empty?
        raise ArgumentError, "#{caller_name}: configure `client_secret` (the app's client credentials)#{action == 'touch' ? ' or `secret_key`' : ''}; a public client cannot call it."
      end
      raise ArgumentError, "A session id (`sid`) is required." if sid.to_s.empty?

      form = [["sid", sid]]
      headers = { "content-type" => "application/x-www-form-urlencoded", "accept" => "application/json" }
      if method == :client_secret_basic
        pair = "#{URI.encode_www_form_component(@config[:client_id])}:#{URI.encode_www_form_component(secret)}"
        headers["authorization"] = "Basic #{Base64.strict_encode64(pair)}"
      else
        form << ["client_id", @config[:client_id]] << ["client_secret", secret]
      end
      status, text, = @http.call("POST", "#{@config[:issuer]}/oauth2/session/#{action}", headers, URI.encode_www_form(form))
      body = begin
        JSON.parse(text.to_s)
      rescue JSON::ParserError
        nil
      end
      [status, body.is_a?(Hash) ? body : nil]
    end

    def oauth_failure(status, body)
      code = body && body["error"].is_a?(String) ? body["error"] : "request_failed"
      message = body && body["error_description"].is_a?(String) ? body["error_description"] : "The issuer answered #{status}."
      Atlas::APIError.new(status, [{ "code" => code, "message" => message }])
    end
  end
end
