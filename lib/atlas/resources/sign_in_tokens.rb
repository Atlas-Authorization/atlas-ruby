# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sign_in_tokens+ — one-time sign-in tokens for a user.
    #
    # @deprecated The sign-in token API is deprecated (sunset 2027-04-01). Use
    #   Sessions#create_browser_ticket: the same one-time ticket, plus a ready URL.
    class SignInTokens < Base
      # @deprecated Use Sessions#create_browser_ticket.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sign_in_tokens", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/sign_in_tokens/:id/revoke+ — revoke an unused sign-in token.
      #
      # @deprecated Use Sessions#create_browser_ticket (or Sessions#create for a
      #   server-side session).
      def revoke(id)
        request(method: :post, path: "/v1/sign_in_tokens/#{enc(id)}/revoke")
      end
    end
  end
end
