# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class ProxyApps < Base
      # List the identity-aware proxy apps — hostnames protected by the forward-auth endpoint, with
      # their path rules.
      # Scope: proxy_apps:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/proxy_apps", query: query)
      end

      # Create a proxy app: a hostname, optional upstream URL, ordered path/method rules requiring a
      # role, permission or entitlement, public paths, and header/token injection. The hostname is
      # unique across the deployment.
      # Scope: proxy_apps:write. query: dry_run. body requires: name, hostname, upstream_url.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/proxy_apps",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one identity-aware proxy app.
      # Scope: proxy_apps:read.
      def get(id)
        request(method: :get, path: "/v1/proxy_apps/#{enc(id)}")
      end

      # Update a proxy app. Omitted fields keep their value.
      # Scope: proxy_apps:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/proxy_apps/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a proxy app. Its hostname stops resolving at the forward-auth endpoint.
      # Scope: proxy_apps:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/proxy_apps/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
