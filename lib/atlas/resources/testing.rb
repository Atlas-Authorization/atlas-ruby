# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Development-instance helpers: the paired test instance, test-user cleanup and testing tokens.
    class Testing < Base
      # +POST /v1/test_instance+ — get (creating on first call) the paired development instance. Pass rotate_secret: true to mint a fresh secret key.
      def test_instance(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/test_instance", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/test_users/purge+ — delete test users in bulk (development instances only). Loop until has_more is false.
      def purge_test_users(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/test_users/purge", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/testing_tokens+ — mint a short-lived testing token (development instances only).
      def create_testing_token
        request(method: :post, path: "/v1/testing_tokens")
      end
    end
  end
end
