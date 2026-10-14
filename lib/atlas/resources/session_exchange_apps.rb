# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/session_exchange_apps+ — downstream apps notified by back-channel logout when an Atlas session ends.
    class SessionExchangeApps < Base
      # +GET /v1/session_exchange_apps+ — registered session-exchange apps and their back-channel logout endpoints.
      def list
        request(method: :get, path: "/v1/session_exchange_apps")
      end

      # +POST /v1/session_exchange_apps+ — register a session-exchange app (name, backchannel_logout_uri, audience).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/session_exchange_apps", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/session_exchange_apps/:id+ — one session-exchange app.
      def get(id)
        request(method: :get, path: "/v1/session_exchange_apps/#{enc(id)}")
      end

      # +PATCH /v1/session_exchange_apps/:id+ — update a session-exchange app.
      def update(id, body, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/session_exchange_apps/#{enc(id)}",
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # +DELETE /v1/session_exchange_apps/:id+ — delete a session-exchange app.
      def delete(id, idempotency_key: nil)
        request(method: :delete, path: "/v1/session_exchange_apps/#{enc(id)}", idempotency_key: idempotency_key)
      end
    end
  end
end
