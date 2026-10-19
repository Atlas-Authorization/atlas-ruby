# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/logout_notify_endpoints+ — logout fan-out ("also notify") endpoints:
    # downstream services that receive the same signed +logout_token+ as your
    # OIDC apps whenever an Atlas session ends, plus a subject-wide one (+sub+,
    # no +sid+) when a user is banned, deleted or deprovisioned.
    class LogoutNotifyEndpoints < Base
      # +GET /v1/logout_notify_endpoints+ — every endpoint.
      def list
        request(method: :get, path: "/v1/logout_notify_endpoints")
      end

      # +POST /v1/logout_notify_endpoints+ — register an endpoint.
      #
      # @param body [Hash] +url+ (public https, required), optional
      #   +oauth_client_id+ (follow one client instead of the whole instance),
      #   +audience+ (the logout_token +aud+; default the client_id, else the
      #   instance id) and +description+ (up to 200 chars).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/logout_notify_endpoints", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/logout_notify_endpoints/:id+ — one endpoint.
      def get(id)
        request(method: :get, path: "/v1/logout_notify_endpoints/#{enc(id)}")
      end

      # +PATCH /v1/logout_notify_endpoints/:id+ — change +url+, +audience+ or +description+.
      def update(id, body, idempotency_key: nil)
        request(method: :patch, path: "/v1/logout_notify_endpoints/#{enc(id)}", body: body,
                idempotency_key: idempotency_key)
      end

      # +DELETE /v1/logout_notify_endpoints/:id+ — delete an endpoint and its queued deliveries.
      def delete(id, idempotency_key: nil)
        request(method: :delete, path: "/v1/logout_notify_endpoints/#{enc(id)}", idempotency_key: idempotency_key)
      end

      # +GET /v1/logout_notify_endpoints/:id/deliveries+ — the delivery log, newest first
      # (+sub+, +sid+ (nil for a subject-wide logout), +status+, +http_status+, +next_retry_at+).
      def list_deliveries(id, params = {})
        request(method: :get, path: "/v1/logout_notify_endpoints/#{enc(id)}/deliveries", query: params)
      end
    end
  end
end
