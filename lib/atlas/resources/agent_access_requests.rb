# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AgentAccessRequests < Base
      # Approve a pending request, optionally for a limited time (expires_in_seconds). 409 when it
      # is no longer pending. Emits agent.access_decided.
      # Scope: machines:write. query: dry_run.
      def approve(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/agent_access_requests/#{enc(id)}/approve",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Deny a pending request. 409 when it is no longer pending. Emits agent.access_decided.
      # Scope: machines:write. query: dry_run.
      def deny(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/agent_access_requests/#{enc(id)}/deny",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List agent access requests, newest first. Filter by status (pending, approved, denied,
      # revoked) or agent_id.
      # Scope: machines:read. query: status, agent_id, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/agent_access_requests", query: query)
      end
    end
  end
end
