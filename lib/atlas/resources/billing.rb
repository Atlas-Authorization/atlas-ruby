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

      # +POST /v1/billing/subjects/:type/:id/sync_seats+ — sync a per-seat subscription's quantity to the organization's current member count.
      def sync_seats(subject_type, subject_id)
        request(method: :post, path: "/v1/billing/subjects/#{enc(subject_type)}/#{enc(subject_id)}/sync_seats")
      end

      # +POST /v1/billing/subscriptions/import+ — adopt an existing Stripe subscription onto an Atlas user or organization without re-charging.
      def import_subscription(body, idempotency_key: nil)
        request(method: :post, path: "/v1/billing/subscriptions/import", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/billing/usage+ — report metered usage for a subject (idempotent on idempotency_key in the body).
      def report_usage(body)
        request(method: :post, path: "/v1/billing/usage", body: body)
      end
    end
  end
end
