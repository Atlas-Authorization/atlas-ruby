# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/mcp+ — the Atlas management MCP server.
    class Mcp < Base
      # +GET /v1/mcp+ — the MCP server descriptor and the tools this key may call.
      def get
        request(method: :get, path: "/v1/mcp")
      end

      # +POST /v1/mcp+ — send one MCP JSON-RPC message (initialize, tools/list, tools/call, ping).
      def call(body)
        request(method: :post, path: "/v1/mcp", body: body)
      end
    end
  end
end
