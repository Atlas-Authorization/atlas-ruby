# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class RelayAgents < Base
      # List the on-prem relay agents with their allowed destinations and whether each is online.
      # Secrets are never returned.
      # Scope: relay_agents:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/relay_agents", query: query)
      end

      # Register an outbound-only relay agent. The response carries the agent token once; it cannot
      # be read back. An agent can reach only the destinations in allowed_destinations (host,
      # host:port, *.domain).
      # Scope: relay_agents:write. query: dry_run. body requires: name.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/relay_agents",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one relay agent, including when it last polled.
      # Scope: relay_agents:read.
      def get(id)
        request(method: :get, path: "/v1/relay_agents/#{enc(id)}")
      end

      # Rename an agent, change its allowed destinations or pinned client-certificate thumbprints,
      # or revoke it (status: revoked).
      # Scope: relay_agents:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/relay_agents/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a relay agent and its queued jobs.
      # Scope: relay_agents:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/relay_agents/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Issue a new agent token (returned once). The old token stops working immediately.
      # Scope: relay_agents:write. query: dry_run.
      def rotate_secret(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/relay_agents/#{enc(id)}/rotate_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
