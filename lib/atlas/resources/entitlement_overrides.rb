# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/entitlement_overrides+ — sales-led plan, feature and limit grants without Stripe.
    class EntitlementOverrides < Base
      # +POST /v1/entitlement_overrides+ — pin a plan, features or limits onto a user or organization without Stripe.
      # Overrides carry +internal+ (hidden from the customer); the create body accepts it too.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/entitlement_overrides", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/entitlement_overrides+ — entitlement overrides, optionally filtered by subject_type and subject_id.
      def list(params = {})
        request(method: :get, path: "/v1/entitlement_overrides", query: params)
      end

      # +DELETE /v1/entitlement_overrides/:id+ — revoke an entitlement override.
      def delete(id)
        request(method: :delete, path: "/v1/entitlement_overrides/#{enc(id)}")
      end
    end
  end
end
