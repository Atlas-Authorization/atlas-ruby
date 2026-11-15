# frozen_string_literal: true

require "active_support/concern"
require_relative "../rp/middleware"

module Atlas
  module Rails
    # Rails glue for the hosted sign-in relying party. Mount the middleware in an initializer:
    #
    #   # config/initializers/atlas_rp.rb
    #   Rails.application.config.middleware.use Atlas::RP::Middleware,
    #     rp: Atlas::RelyingParty.new(issuer: ENV["ATLAS_ISSUER"], client_id: ENV["ATLAS_CLIENT_ID"],
    #                                 client_secret: ENV["ATLAS_CLIENT_SECRET"], redirect_uri: "https://app.example.com/auth/callback",
    #                                 secret: ENV["SESSION_SECRET"], secret_key: ENV["ATLAS_SECRET_KEY"]),
    #     session: Atlas::RP::Session.new(secret: ENV["SESSION_SECRET"])
    #
    # then include the helpers:
    #
    #   class ApplicationController < ActionController::Base
    #     include Atlas::Rails::RelyingPartyController
    #     before_action :require_atlas_sign_in!
    #   end
    module RelyingPartyController
      extend ActiveSupport::Concern

      included do
        helper_method :atlas_user, :atlas_signed_in? if respond_to?(:helper_method)
      end

      # The signed-in user's session Hash (+sub+, +sid+, +email+, +name+, +org_id+, +auth_time+, ...), or nil.
      def atlas_user = request.env[Atlas::RP::Middleware::ENV_KEY]
      def atlas_signed_in? = !atlas_user.nil?

      # +before_action+ guard: send the user to the hosted sign-in (coming back here) unless signed in.
      def require_atlas_sign_in!(sign_in_path: "/auth/sign-in")
        return true if atlas_signed_in?

        redirect_to "#{sign_in_path}?#{URI.encode_www_form('return_to' => request.fullpath)}", allow_other_host: false
        false
      end

      # +before_action+ guard for step-up: ask the user to authenticate again unless they did within
      # +max_age_seconds+ (0 asks every time).
      def require_atlas_recent_auth!(max_age_seconds)
        triple = Atlas::RP::Helpers.require_recent_auth(request.env, max_age_seconds)
        return true unless triple

        redirect_to triple[1]["location"], allow_other_host: true
        false
      end
    end
  end
end
