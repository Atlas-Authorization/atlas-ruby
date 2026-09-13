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

      # Delivery log for an endpoint.
      def deliveries(id)
        request(method: :get, path: "/v1/webhook_endpoints/#{enc(id)}/deliveries")
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
      end
    end
  end
end
