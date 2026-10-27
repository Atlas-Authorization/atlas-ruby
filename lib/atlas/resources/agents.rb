# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Agents < Base
      # Backend-assisted claim: bind an agent to a user you already know and promote it to trusted.
      # Audited as agent.claimed.
      # Scope: machines:write. query: dry_run. body requires: user_id.
      def claim(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/agents/#{enc(id)}/claim",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # The agent registry: every registered agent with its tier, owner and status. Filter by
      # owner_user_id or tier; page with limit and starting_after.
      # Scope: machines:read. query: owner_user_id, tier, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/agents", query: query)
      end

      # One agent with its currently valid access grants.
      # Scope: machines:read.
      def get(id)
        request(method: :get, path: "/v1/agents/#{enc(id)}")
      end

      # Set the owning user of an agent, or null to remove the owner (which also drops the agent
      # back to untrusted).
      # Scope: machines:write. query: dry_run. body requires: user_id.
      def set_owner(id, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/agents/#{enc(id)}/owner",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Revoke every grant and cancel every pending request of an agent. With disable: true the
      # agent itself is revoked and can no longer get tokens. Emits agent.access_revoked.
      # Scope: machines:write. query: dry_run.
      def revoke_access(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/agents/#{enc(id)}/revoke_access",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
