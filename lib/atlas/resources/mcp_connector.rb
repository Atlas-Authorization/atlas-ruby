# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/mcp_connector+ — the instance's OAuth-protected remote MCP connector.
    class McpConnector < Base
      # +GET /v1/mcp_connector+ — the remote MCP connector settings and its discovery URL.
      def get
        request(method: :get, path: "/v1/mcp_connector")
      end

      # +PUT /v1/mcp_connector+ — configure the remote MCP connector. Only the fields you send change.
      def update(body, idempotency_key: nil)
        request(method: :put, path: "/v1/mcp_connector", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/mcp_connector+ — disable the remote MCP connector (its settings are kept for a later re-enable).
      def disable(idempotency_key: nil)
        request(method: :delete, path: "/v1/mcp_connector", idempotency_key: idempotency_key)
      end
    end
  end
end
