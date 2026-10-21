# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/webhook_endpoints+ — outbound webhook endpoints and their delivery log.
    class Webhooks < Base
      # +webhooks.endpoints+ — CRUD over endpoints.
      def endpoints
        @endpoints ||= Endpoints.new(@transport)
      end

      # Delivery log for an endpoint, newest first. +params+: +limit+ (default 50, max 100).
      def deliveries(id, params = {})
        request(method: :get, path: "/v1/webhook_endpoints/#{enc(id)}/deliveries", query: params)
      end

      class Endpoints < Base
        def list
          request(method: :get, path: "/v1/webhook_endpoints")
        end

        # Create reveals the signing secret (+whsec_...+) exactly once.
        def create(body, idempotency_key: nil)
          request(method: :post, path: "/v1/webhook_endpoints", body: body, idempotency_key: idempotency_key)
        end

        def delete(id)
          request(method: :delete, path: "/v1/webhook_endpoints/#{enc(id)}")
        end

        # +PATCH /v1/webhook_endpoints/:id+ — update an endpoint's url, enabled_events or active flag. The signing secret is kept.
        def update(id, body)
          request(method: :patch, path: "/v1/webhook_endpoints/#{enc(id)}", body: body)
        end

        # +POST /v1/webhook_endpoints/:id/reveal_secret+ — show the endpoint's current signing secret again. Does not change it.
        def reveal_secret(id)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/reveal_secret")
        end

        # +POST /v1/webhook_endpoints/:id/rotate_secret+ — rotate the signing secret. The new secret is shown once.
        # By default the old secret stops signing at once. With +{ overlap_seconds: }+ (at most 604800) every
        # delivery is signed with both until +previous_secret_expires_at+ (epoch ms), so a verifier holding
        # either passes. Choose an overlap only once every receiver accepts several signatures (0.7.0+).
        def rotate_secret(id, body = Atlas::Transport::OMIT)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/rotate_secret", body: body)
        end

        # +POST /v1/webhook_endpoints/:id/test+ — send a synthetic webhook.test event to this endpoint only.
        def test(id)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/test")
        end
      end

      # +POST /v1/webhook_endpoints/:id/deliveries/:deliveryId/redeliver+ — redeliver a past event as a fresh attempt.
      def redeliver(endpoint_id, delivery_id)
        request(
          method: :post,
          path: "/v1/webhook_endpoints/#{enc(endpoint_id)}/deliveries/#{enc(delivery_id)}/redeliver"
        )
      end
    end
  end
end
