# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/actions+ — tenant code run in the hardened isolate at auth triggers,
    # plus the per-trigger binding lists.
    class Actions < Base
      def list
        request(method: :get, path: "/v1/actions")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/actions", body: body, idempotency_key: idempotency_key)
      end

      def get(id)
        request(method: :get, path: "/v1/actions/#{enc(id)}")
      end

      def update(id, body)
        request(method: :patch, path: "/v1/actions/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/actions/#{enc(id)}")
      end

      # Dry-run against a sample event in the sandbox; nothing is persisted.
      def test(id, event = {})
        request(method: :post, path: "/v1/actions/#{enc(id)}/test", body: { event: event })
      end

      # The actions bound to a trigger, in run order.
      def get_bindings(trigger)
        request(method: :get, path: "/v1/actions/bindings/#{enc(trigger)}")
      end

      # Replace a trigger's ordered binding set.
      def set_bindings(trigger, action_ids)
        request(method: :put, path: "/v1/actions/bindings/#{enc(trigger)}", body: { action_ids: action_ids })
      end
    end
  end
end
