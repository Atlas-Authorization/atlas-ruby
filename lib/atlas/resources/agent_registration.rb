# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AgentRegistration < Base
      # Read the agent registration settings (enabled, allowed identity kinds, untrusted and trusted
      # scopes, claim code lifetime).
      # Scope: machines:read.
      def get
        request(method: :get, path: "/v1/agent_registration")
      end

      # Update the agent registration settings. Partial: only the fields sent change.
      # Scope: machines:write. query: dry_run.
      def replace(body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/agent_registration",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
