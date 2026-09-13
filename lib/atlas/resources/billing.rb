# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/billing+ — the plans a tenant defines for its users, and the read-only
    # subscription view.
    class Billing < Base
      def list_plans
        request(method: :get, path: "/v1/billing/plans")
      end

      def create_plan(body, idempotency_key: nil)
        request(method: :post, path: "/v1/billing/plans", body: body, idempotency_key: idempotency_key)
      end

      def get_plan(id)
        request(method: :get, path: "/v1/billing/plans/#{enc(id)}")
      end

      def update_plan(id, body)
        request(method: :patch, path: "/v1/billing/plans/#{enc(id)}", body: body)
      end

      def delete_plan(id)
        request(method: :delete, path: "/v1/billing/plans/#{enc(id)}")
      end

      def list_subscriptions(params = nil)
        request(method: :get, path: "/v1/billing/subscriptions", query: params)
      end
    end
  end
end
