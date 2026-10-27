# frozen_string_literal: true

require_relative "organizations"

module Atlas
  module Resources
    class Organizations
      # List the apps (OAuth clients) that hold an active grant in this organization's context, one
      # entry per grant.
      # Scope: organizations:read. query: limit, starting_after.
      def list_connected_apps(id, query = nil)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/connected_apps", query: query)
      end

      # Revoke one connected app grant of the organization: its tokens and any session minted from
      # it stop working. Emits grant.revoked; audited as organization.connected_app_revoked.
      # Scope: organizations:write. query: dry_run.
      def revoke_connected_app(id, grant_id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/organizations/#{enc(id)}/connected_apps/#{enc(grant_id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # The same read, scoped to an organization: 404 unless the connection is owned by that
      # organization. Needs connections:secret_read; audited.
      # Scope: connections:secret_read. query: version.
      def get_connection_secret(id, connection_id, query = nil)
        request(
          method: :get,
          path: "/v1/organizations/#{enc(id)}/connections/#{enc(connection_id)}/secret",
          query: query
        )
      end

      def webhook_endpoints
        @webhook_endpoints ||= WebhookEndpoints.new(@transport)
      end

      class WebhookEndpoints < Base
        # List the organization's own webhook endpoints. Backend API. Never returns a secret.
        # Scope: webhooks:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/organizations/#{enc(id)}/webhook_endpoints", query: query)
        end

        # Register a webhook endpoint for one organization. It receives only that organization's
        # events (membership, invitation, role, domain and organization events). The signing secret
        # is returned in this response only. Backend API. At most 20 per organization.
        # Scope: webhooks:write. query: dry_run.
        def create(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/organizations/#{enc(id)}/webhook_endpoints",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Retrieve one of the organization's webhook endpoints, with its delivery health.
        # Scope: webhooks:read.
        def get(id, endpoint_id)
          request(method: :get, path: "/v1/organizations/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}")
        end

        # Update the url, subscribed events, description or active flag of one of the organization's
        # endpoints. Never re-reveals the secret.
        # Scope: webhooks:write. query: dry_run.
        def update(id, endpoint_id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/organizations/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete one of the organization's webhook endpoints and its delivery log. An id from
        # another organization is a 404.
        # Scope: webhooks:write. query: dry_run.
        def delete(id, endpoint_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/organizations/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Rotate the signing secret. The previous secret keeps signing alongside the new one for 24
        # hours so the receiver can switch over without dropping events.
        # Scope: webhooks:write. query: dry_run.
        def rotate_secret(id, endpoint_id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/organizations/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}/rotate_secret",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # The endpoint's delivery log: payload, response and retry state for each attempt,
        # filterable by status, event type and time.
        # Scope: webhooks:read. query: limit, starting_after, status, event_type, since, until,
        # trace.
        def deliveries(id, endpoint_id, query = nil)
          request(
            method: :get,
            path: "/v1/organizations/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}/deliveries",
            query: query
          )
        end
      end
    end
  end
end
