# frozen_string_literal: true

require "active_support/concern"

module Atlas
  module Rails
    # Controller mix-in exposing the request's Atlas session.
    #
    # The {Atlas::Rails::Middleware} has already verified the token by the time
    # an action runs, so these helpers only read +env["atlas.auth"]+ — they
    # never touch crypto.
    #
    #   class ApplicationController < ActionController::Base
    #     include Atlas::Rails::Controller
    #   end
    #
    #   class BillingController < ApplicationController
    #     before_action :require_atlas_auth!
    #     before_action -> { atlas_authorize!(permission: "org:billing:manage") }
    #
    #     def show
    #       render json: { user: current_atlas_user_id }
    #     end
    #   end
    module Controller
      extend ActiveSupport::Concern

      # The verified {Atlas::VerifyResult} for this request (ok or failed), or a
      # failure result when the middleware is not in the stack.
      # @return [Atlas::VerifyResult]
      def current_atlas_session
        request.env[Atlas::Rails::Middleware::ENV_KEY] ||
          Atlas::VerifyResult.failure(:invalid)
      end

      # The verified claims hash (string-keyed), or nil when unauthenticated.
      # @return [Hash, nil]
      def current_atlas_claims
        session = current_atlas_session
        session.ok? ? session.claims : nil
      end

      # The authenticated user id (+sub+), or nil.
      # @return [String, nil]
      def current_atlas_user_id
        current_atlas_claims&.fetch("sub", nil)
      end

      # True when this request carries a valid Atlas session.
      def atlas_authenticated?
        current_atlas_session.ok?
      end

      # +before_action+ guard: render 401 and halt unless authenticated.
      def require_atlas_auth!
        return true if atlas_authenticated?

        render_atlas_unauthorized
        false
      end

      # +before_action+ guard for a specific authorization condition, e.g.
      # +atlas_authorize!(permission: "org:billing:manage")+. Renders 401 when
      # unauthenticated and 403 when authenticated but not permitted. Accepts the
      # same conditions as {Atlas::VerifyResult#has?}
      # (+:permission+, +:role+, +:any_permission+, +:all_permissions+).
      def atlas_authorize!(**condition)
        unless atlas_authenticated?
          render_atlas_unauthorized
          return false
        end

        unless current_atlas_session.has?(condition)
          render_atlas_forbidden
          return false
        end

        true
      end

      private

      def render_atlas_unauthorized
        render json: {
          errors: [{ "code" => "UNAUTHENTICATED", "message" => "Authentication required." }],
        }, status: :unauthorized
      end

      def render_atlas_forbidden
        render json: {
          errors: [{ "code" => "FORBIDDEN", "message" => "You do not have permission to do that." }],
        }, status: :forbidden
      end
    end
  end
end
