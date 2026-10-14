# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/usage+ — usage analytics.
    class Usage < Base
      # +GET /v1/usage+ — usage analytics: daily sign-in and active-user series plus monthly active users.
      def get(params = {})
        request(method: :get, path: "/v1/usage", query: params)
      end
    end
  end
end
