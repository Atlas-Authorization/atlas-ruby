# frozen_string_literal: true

require_relative "http"
require_relative "session"
require_relative "relying_party"

module Atlas
  module RP
    # Rack middleware that mounts the hosted sign-in on any Rack app (Rails, Sinatra, Hanami, plain Rack).
    #
    # It answers the sign-in, callback, sign-out (and back-channel logout) paths, keeps your session in a
    # sealed cookie ({Atlas::RP::Session}), keeps the Atlas session alive with +touch_if_due+, and leaves the
    # signed-in user at +env["atlas.rp.session"]+ (a Hash, or nil when signed out) for the rest of your stack.
    # Every other request passes through; enforcing sign-in is the app's job ({Atlas::RP::Helpers}).
    #
    #   use Atlas::RP::Middleware,
    #       rp: Atlas::RelyingParty.new(issuer: ..., client_id: ..., client_secret: ..., redirect_uri: ..., secret: ...),
    #       session: Atlas::RP::Session.new(secret: ENV["SESSION_SECRET"])
    class Middleware
      ENV_KEY = "atlas.rp.session"
      RP_KEY = "atlas.rp"

      # @param rp [Atlas::RelyingParty]
      # @param session [Atlas::RP::Session]
      # @param touch [Boolean] keep the Atlas session alive on each authenticated request.
      # @param store_id_token [Boolean] keep the ID token in the cookie (the sign-out hint). Default true.
      # @param on_signed_in [#call, nil] +(user, tokens, request, result)+ run after the session cookie is set
      #   (create your own user row here); a Response it returns replaces the redirect.
      def initialize(app, rp:, session:, touch: true, store_id_token: true, on_signed_in: nil)
        @app = app
        @rp = rp
        @session = session
        @touch = touch
        @store_id_token = store_id_token
        @after_sign_in = on_signed_in
      end

      def call(env)
        request = Request.from_rack(env)
        current = @session.read(request.cookie_header)
        answer = @rp.handle(request, on_signed_in: method(:signed_in), on_sign_out: ->(_req) { sign_out_options(current) })
        return answer.to_rack if answer

        extra = []
        if current && @touch && current["sid"]
          current, extra = touch(current)
        end
        env[ENV_KEY] = current
        env[RP_KEY] = @rp
        status, headers, body = @app.call(env)
        Response.merge_cookies(headers, extra)
        [status, headers, body]
      end

      private

      def signed_in(user, tokens, request, result)
        data = { "sub" => user.sub, "sid" => user.sid, "email" => user.email, "email_verified" => user.email_verified,
                 "name" => user.name, "external_id" => user.external_id, "org_id" => user.org_id,
                 "org_role" => user.org_role, "auth_time" => user.auth_time, "touched_at" => Time.now.to_i }
        data["id_token"] = tokens.id_token if @store_id_token
        data.compact!
        response = @after_sign_in&.call(user, tokens, request, result)
        response = result.response unless response.is_a?(Response)
        response.add_cookie(@session.build(data))
      end

      def sign_out_options(current)
        { sid: current && current["sid"], id_token: current && current["id_token"], set_cookies: [@session.clear] }
      end

      # @return [Array(Hash, Array<String>)] the (possibly refreshed or dropped) session and cookies to set.
      def touch(current)
        result = @rp.touch_if_due(current["sid"], current["touched_at"])
        case result[:status]
        when :touched
          fresh = current.merge("touched_at" => result[:last_touched_at])
          [fresh, [@session.build(fresh.reject { |k, _| k == "exp" })]]
        when :ended then [nil, [@session.clear]]
        else [current, []]
        end
      end
    end

    # Request-level helpers for code that already holds the Rack env (controllers, Sinatra routes, Rack apps).
    module Helpers
      module_function

      # The signed-in user's session Hash from the env, or nil.
      def current_session(env) = env[Middleware::ENV_KEY]

      def signed_in?(env) = !current_session(env).nil?

      # A 302 to the hosted sign-in that comes back to the current page, as a Rack triple.
      def sign_in_redirect(env, sign_in_path: "/auth/sign-in")
        request = Request.from_rack(env)
        target = URI.encode_www_form("return_to" => request.path_and_query)
        Response.redirect("#{sign_in_path}?#{target}").to_rack
      end

      # Step-up: nil when the current session authenticated within +max_age_seconds+; otherwise a Rack triple
      # sending the user to re-authenticate.
      def require_recent_auth(env, max_age_seconds)
        session = current_session(env)
        return sign_in_redirect(env) unless session

        rp = env[Middleware::RP_KEY] or raise Atlas::ConfigurationError, "Atlas::RP::Middleware is not in the stack."
        rp.require_recent_auth(Request.from_rack(env), max_age_seconds, sub: session["sub"], auth_time: session["auth_time"])&.to_rack
      end
    end
  end
end
