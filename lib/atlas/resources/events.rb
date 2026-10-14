# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/events+ — the product activity feed.
    class Events < Base
      # +GET /v1/events+ — the product activity feed, filterable by type and time. Cursor-paginated.
      def list(params = {})
        request(method: :get, path: "/v1/events", query: params)
      end
    end
  end
end
