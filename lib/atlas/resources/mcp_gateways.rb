# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class McpGateways < Base
      # List the MCP tool gateways of the instance.
      # Scope: machines:read.
      def list
        request(method: :get, path: "/v1/mcp_gateways")
      end

      # Create an MCP gateway: one URL (+url+ in the response) that fronts your MCP server. +tools+
      # maps a tool name to its policy (allow, scopes the agent token must hold, argument
      # conditions, approval, response masking); +default_policy+ (deny by default) decides tools
      # not listed. upstream_authorization is write-only and sent to the upstream as its
      # Authorization header.
      # Scope: machines:write. query: dry_run. body requires: name, upstream_url.
      def create(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/mcp_gateways",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one MCP gateway.
      # Scope: machines:read.
      def get(id)
        request(method: :get, path: "/v1/mcp_gateways/#{enc(id)}")
      end

      # Update an MCP gateway. Omitted fields keep their value; +tools+ is replaced as a whole.
      # +abac+ turns on authorization of every tool call through the ABAC policy engine.
      # Scope: machines:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/mcp_gateways/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete an MCP gateway.
      # Scope: machines:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/mcp_gateways/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      def budgets
        @budgets ||= Budgets.new(@transport)
      end

      class Budgets < Base
        # The cross-call budgets of a gateway, newest first (at most 50): ceilings on how many
        # calls, how much cost, or how many calls per window one agent or one session may make.
        # Scope: machines:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/mcp_gateways/#{enc(id)}/budgets", query: query)
        end

        # Add a budget. +metric+ is +calls+ (a count), +cost+ (the sum of each call's cost:
        # +cost_per_call+, or the number found at +cost_arg+ in the call arguments, such as an
        # amount) or +rate+ (calls per +window_seconds+, required). +limit+ is the ceiling.
        # +window_seconds+ makes the counter reset in fixed windows; without it a counter never
        # resets (a per-session one ends with the session). +scope+ is +agent+ (each agent counts
        # separately) or +session+ (each session of each agent; the client must echo the
        # +Mcp-Session-Id+ from initialize). +agent_id+ limits it to one agent and +tool+ to one
        # tool. A call is charged against every budget it touches at once, or against none; only a
        # call that is allowed and about to run is charged.
        # Scope: machines:write. query: dry_run.
        def create(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/mcp_gateways/#{enc(id)}/budgets",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one budget of an MCP gateway.
        # Scope: machines:read.
        def get(id, budget_id)
          request(method: :get, path: "/v1/mcp_gateways/#{enc(id)}/budgets/#{enc(budget_id)}")
        end

        # Change a budget. Omitted fields keep their value. Raising the limit takes effect on the
        # next call; counters are kept.
        # Scope: machines:write. query: dry_run.
        def update(id, budget_id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/mcp_gateways/#{enc(id)}/budgets/#{enc(budget_id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a budget and stop counting against it.
        # Scope: machines:write. query: dry_run.
        def delete(id, budget_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/mcp_gateways/#{enc(id)}/budgets/#{enc(budget_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # What one agent has used of a budget right now, with the room left and when the window
        # resets. A per-session budget also needs the +session_id+ (the Mcp-Session-Id of that
        # session).
        # Scope: machines:read. query: agent_id, session_id.
        def usage(id, budget_id, query = nil)
          request(
            method: :get,
            path: "/v1/mcp_gateways/#{enc(id)}/budgets/#{enc(budget_id)}/usage",
            query: query
          )
        end
      end
    end
  end
end
