# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/risk_based_mfa+ — the adaptive / risk-based MFA engine config.
    class RiskBasedMfa < Base
      def get
        request(method: :get, path: "/v1/risk_based_mfa")
      end

      def update(body)
        request(method: :patch, path: "/v1/risk_based_mfa", body: body)
      end
    end
  end
end
