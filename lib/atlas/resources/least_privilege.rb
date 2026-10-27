# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class LeastPrivilege < Base
      # The least-privilege report: for every active secret key, OAuth client, MCP gateway and
      # agent, what it is allowed to do against what it used over the window, the permissions never
      # used, and the narrower grant that would still cover its use. Credentials with something
      # unused come first. +format=csv+ exports one row per permission.
      # Scope: least_privilege:read. query: days, subject_type, subject_id, only_unused, limit,
      # format, starting_after.
      def report(query = nil)
        request(method: :get, path: "/v1/least_privilege/report", query: query)
      end

      # The least-privilege report of one credential (+type+ is api_key, oauth_client, mcp_gateway
      # or agent). 404 for a credential the report does not cover, such as a revoked key.
      # Scope: least_privilege:read. query: days.
      def get(type, id, query = nil)
        request(method: :get, path: "/v1/least_privilege/report/#{enc(type)}/#{enc(id)}", query: query)
      end

      # Apply a credential's suggestion: narrow a secret key's scopes, an OAuth client's allowed
      # scopes, an MCP gateway's tool policy, or revoke an agent's unused tool grants. Preview it
      # first with +?dry_run=true+, then send the same body for real. +digest+ (from the report)
      # must match the current suggestion, else 409, so what you previewed is what is applied; the
      # write is conditional on the credential being unchanged. A suggestion only ever removes
      # permissions. Over a window the data does not fully cover (+confidence: low+) it needs
      # +acknowledge_short_window: true+. Audited as +least_privilege.applied+.
      # Scope: least_privilege:write. query: dry_run.
      def apply(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/least_privilege/apply",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
