# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/tickets+ — one-time capability tickets.
    class Tickets < Base
      # +POST /v1/tickets+ — mint a one-time capability ticket. The tkt_ secret is returned once.
      def create(body)
        request(method: :post, path: "/v1/tickets", body: body)
      end

      # +POST /v1/tickets/redeem+ — redeem a ticket server-to-server and return its payload.
      def redeem(body)
        request(method: :post, path: "/v1/tickets/redeem", body: body)
      end
    end
  end
end
