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

      # +POST /v1/testing/sign_in_url+ — a ready one-time URL that signs a browser in
      # as +user_id+ and lands on +redirect_url+ (an allowed origin or localhost).
      # Development instances only (403 +TESTING_UNAVAILABLE+ otherwise). Returns
      # +{ "object" => "testing_sign_in_url", "id", "user_id", "ticket", "url",
      # "redirect_url", "expires_in", "expires_at" }+.
      def create_sign_in_url(user_id, redirect_url, expires_in_seconds: nil)
        body = { user_id: user_id, redirect_url: redirect_url }
        body[:expires_in_seconds] = expires_in_seconds unless expires_in_seconds.nil?
        request(method: :post, path: "/v1/testing/sign_in_url", body: body)
      end
    end
  end
end
