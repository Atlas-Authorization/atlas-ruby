# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/rate_limit_policy+ — the two tunable budgets over the built-in limiter.
    class RateLimitPolicy < Base
      def get
        request(method: :get, path: "/v1/rate_limit_policy")
      end

      def update(body)
        request(method: :patch, path: "/v1/rate_limit_policy", body: body)
      end
    end
  end
end
