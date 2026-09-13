# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sessions+ — mint, list, inspect, and revoke sessions.
    class Sessions < Base
      # +POST /v1/sessions+ — mint a session for a user without the sign-in flow.
      # Returns the bearer jwt + refresh token in-body. Refused for a banned user.
      def create(params)
        request(method: :post, path: "/v1/sessions", body: params)
      end

      # +GET /v1/sessions?user_id=+ — requires a +user_id+.
      def list(params)
        request(method: :get, path: "/v1/sessions", query: params)
      end

      def get(id)
        request(method: :get, path: "/v1/sessions/#{enc(id)}")
      end

      def revoke(id)
        request(method: :post, path: "/v1/sessions/#{enc(id)}/revoke")
      end
    end
  end
end
