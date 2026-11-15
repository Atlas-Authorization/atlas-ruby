# frozen_string_literal: true

require_relative "middleware"

module Atlas
  module RP
    # Sinatra extension: installs {Atlas::RP::Middleware} and adds route helpers.
    #
    #   class App < Sinatra::Base
    #     register Atlas::RP::Sinatra
    #     set :atlas_rp, Atlas::RelyingParty.new(...)
    #     set :atlas_session, Atlas::RP::Session.new(secret: ENV["SESSION_SECRET"])
    #     Atlas::RP::Sinatra.use!(self)   # mounts the sign-in routes and the session
    #
    #     get("/account") { atlas_require_sign_in! ; "Hello #{atlas_user['email']}" }
    #   end
    module Sinatra
      module Helpers
        # The signed-in user's session Hash, or nil.
        def atlas_user = request.env[Atlas::RP::Middleware::ENV_KEY]
        def atlas_signed_in? = !atlas_user.nil?

        # Halt with a redirect to the hosted sign-in unless signed in.
        def atlas_require_sign_in!(sign_in_path: "/auth/sign-in")
          return atlas_user if atlas_user

          redirect "#{sign_in_path}?#{URI.encode_www_form('return_to' => request.fullpath)}"
        end

        # Halt with a redirect that asks the user to authenticate again unless they did within +max_age_seconds+.
        def atlas_require_recent_auth!(max_age_seconds)
          triple = Atlas::RP::Helpers.require_recent_auth(request.env, max_age_seconds)
          halt triple if triple
        end
      end

      def self.registered(app)
        app.helpers Helpers
        app.set :atlas_rp, nil unless app.respond_to?(:atlas_rp)
        app.set :atlas_session, nil unless app.respond_to?(:atlas_session)
      end

      # Add the middleware to +app+ (call after +set :atlas_rp+ and +set :atlas_session+).
      def self.use!(app, **options)
        app.use Atlas::RP::Middleware, rp: app.settings.atlas_rp, session: app.settings.atlas_session, **options
      end
    end
  end
end
