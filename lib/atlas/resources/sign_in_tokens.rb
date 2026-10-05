# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sign_in_tokens+ — one-time sign-in tokens for a user.
    #
    # @deprecated POST /v1/sign_in_tokens is deprecated (Sunset 2026-04-01). Use
    #   Sessions#create (POST /v1/sessions), which mints a real redeemable session.
    class SignInTokens < Base
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sign_in_tokens", body: body, idempotency_key: idempotency_key)
      end
    end
  end
end
