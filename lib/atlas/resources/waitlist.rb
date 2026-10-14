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

      # +POST /v1/waitlist_entries+ — add an address to the waitlist (idempotent on the address).
      def create(email_address)
        request(method: :post, path: "/v1/waitlist_entries", body: { email_address: email_address })
      end

      # +POST /v1/waitlist_entries/bulk+ — add up to 100 addresses; per-entry errors are returned.
      def bulk_create(email_addresses)
        request(method: :post, path: "/v1/waitlist_entries/bulk", body: { email_addresses: email_addresses })
      end

      # +DELETE /v1/waitlist_entries/:id+ — delete a waitlist entry.
      def delete(id)
        request(method: :delete, path: "/v1/waitlist_entries/#{enc(id)}")
      end
    end
  end
end
