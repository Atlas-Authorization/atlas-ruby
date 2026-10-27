# frozen_string_literal: true

require_relative "actions"

module Atlas
  module Resources
    class Actions
      # The call log of an +http+ Action (an Action that calls your own endpoint), newest first,
      # with 24 hour stats: calls, denied, failed, timeouts and p95 latency. Real calls and dry-run
      # tests are both logged (+test+). 409 for a +node+ Action.
      # Scope: actions:read. query: limit, status, test, starting_after.
      def calls(id, query = nil)
        request(method: :get, path: "/v1/actions/#{enc(id)}/calls", query: query)
      end
    end
  end
end
