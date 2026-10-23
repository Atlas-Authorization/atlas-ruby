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

      # +POST /v1/billing/subscriptions/:id/change+ — switch to another plan or
      # interval on the billing provider: +{ plan_id:, interval: "month"|"year",
      # schedule_at_period_end: true }+ (default: now, prorated).
      def change_subscription(id, body)
        request(method: :post, path: "/v1/billing/subscriptions/#{enc(id)}/change", body: body)
      end

      # +POST /v1/billing/subscriptions/:id/cancel+ — at the period end, or now
      # with +immediately: true+.
      def cancel_subscription(id, immediately: false)
        body = immediately ? { immediately: true } : {}
        request(method: :post, path: "/v1/billing/subscriptions/#{enc(id)}/cancel", body: body)
      end

      # +POST /v1/billing/subscriptions/:id/restore+ — undo a scheduled cancellation.
      def restore_subscription(id)
        request(method: :post, path: "/v1/billing/subscriptions/#{enc(id)}/restore")
      end

      # +GET /v1/billing/providers+ — the providers (stripe, polar, dodo, creem)
      # this instance has its OWN credentials for. Secrets are never returned
      # (+secrets_set+ markers only); each carries the +webhook_url+ to register.
      def list_providers
        request(method: :get, path: "/v1/billing/providers")
      end

      def get_provider(provider)
        request(method: :get, path: "/v1/billing/providers/#{enc(provider)}")
      end

      # +PUT /v1/billing/providers/:provider+ — +{ environment:, config: {...} }+,
      # merged onto what is stored. Stripe: +secret_key+, +webhook_secret+,
      # +publishable_key+; Polar: +access_token+, +webhook_secret+; Dodo and Creem:
      # +api_key+, +webhook_secret+.
      def set_provider(provider, body)
        request(method: :put, path: "/v1/billing/providers/#{enc(provider)}", body: body)
      end

      # One read-only call with the stored credentials: +{ ok:, error:, account: }+.
      def test_provider(provider)
        request(method: :post, path: "/v1/billing/providers/#{enc(provider)}/test")
      end

      # Refused while live subscriptions or plans depend on it unless +force: true+.
      def delete_provider(provider, force: false)
        request(method: :delete, path: "/v1/billing/providers/#{enc(provider)}", query: force ? { force: "true" } : nil)
      end
    end
  end
end
