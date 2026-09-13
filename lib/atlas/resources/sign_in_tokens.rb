# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sign_in_tokens+ — one-time sign-in tokens for a user.
    class SignInTokens < Base
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sign_in_tokens", body: body, idempotency_key: idempotency_key)
      end
    end
  end
end
