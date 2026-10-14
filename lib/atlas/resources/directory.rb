# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/directory+ — the unified connector directory.
    class Directory < Base
      # +GET /v1/directory+ — the connector directory: built-in providers plus published community connectors.
      def list(params = {})
        request(method: :get, path: "/v1/directory", query: params)
      end
    end
  end
end
