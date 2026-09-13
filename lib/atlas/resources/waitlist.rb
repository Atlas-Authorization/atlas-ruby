# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/waitlist_entries+ — the sign-up waitlist and its approve/deny decisions.
    class Waitlist < Base
      def list(params = {})
        request(method: :get, path: "/v1/waitlist_entries", query: params)
      end

      # Approve or deny a waitlist entry.
      def decide(id, body)
        request(method: :post, path: "/v1/waitlist_entries/#{enc(id)}/decide", body: body)
      end
    end
  end
end
