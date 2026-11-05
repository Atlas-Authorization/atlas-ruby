# frozen_string_literal: true

require_relative "instance"

module Atlas
  module Resources
    class Instance
      def integrations
        @integrations ||= Integrations.new(@transport)
      end

      class Integrations < Base
        # Rotate the signing secret of the integration's event receiver. The new secret is revealed
        # exactly once. By default (+overlap_seconds+ 0) the old secret stops signing at once. With
        # +overlap_seconds+ (at most 604800 = 7 days) every delivery carries two signatures in
        # +Atlas-Signature+ (+v1,<new> v1,<old>+, the new one first), so the service verifies with
        # either secret while it deploys the new one; after that only the new secret signs.
        # +previous_secret_expires_at+ says when the old secret stops signing (epoch ms), or null
        # when it already has. Audited as integration.<id>.events_secret_rotated. 404 when the
        # integration has no event receiver.
        # Scope: instance:write. query: dry_run.
        def rotate_events_secret(product, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/instance/integrations/#{enc(product)}/events_secret/rotate",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +POST /v1/instance/integrations/:product/deliveries/redeliver+ - Re-send the events the
        # integration's receiver never got, and switch a disabled receiver back on. Delivered events
        # are not sent again. While +has_more+ is true, call again with +since+ set to +next_since+.
        # Scope: instance:write. Body requires: since (ISO 8601, epoch ms or failing_since).
        def redeliver_events(product, body, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/instance/integrations/#{enc(product)}/deliveries/redeliver",
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
