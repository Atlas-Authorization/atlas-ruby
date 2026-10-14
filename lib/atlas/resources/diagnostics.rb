# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/diagnostics+ — explain why sign-in or a browser request fails.
    class Diagnostics < Base
      # +GET /v1/diagnostics/login_readiness+ — end-to-end login-readiness check for an origin (CORS, cookie domain, email claim, signing keys). Pass live: true for a real key round trip.
      def login_readiness(params = {})
        request(method: :get, path: "/v1/diagnostics/login_readiness", query: params)
      end

      # +GET /v1/diagnostics/request_inspector+ — explain why a browser request would be rejected (origin required; method, path, token optional).
      def request_inspector(params = {})
        request(method: :get, path: "/v1/diagnostics/request_inspector", query: params)
      end
    end
  end
end
