# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/events+ — the product activity feed.
    class Events < Base
      # +GET /v1/events+ — the product activity feed, filterable by type and time. Cursor-paginated.
      # +params+: +type+, +since+, +until+ (epoch ms or ISO 8601), +order+ (+asc+ / +desc+),
      # +limit+, +starting_after+, +trace+. The response carries +retention+ (how far back events are kept).
      def list(params = {})
        request(method: :get, path: "/v1/events", query: params)
      end
    end
  end
end
