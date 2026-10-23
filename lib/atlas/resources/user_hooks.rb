# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance/hooks+ — the +before_user_create+ hook. Just before Atlas
    # creates a user from a self-service sign-up, it sends your endpoint a
    # signed +POST+ (the webhook headers; verify it with +Atlas::Webhook+) of
    # type +user.before_create+, with +data+ +{ user, strategy, referral }+, and
    # stamps the +external_id+ and metadata you answer. A slow or failing hook
    # never blocks a sign-up. +signing_secret+ is write-only: reads return
    # +signing_secret_set+.
    class UserHooks < Base
      # +enabled+, +url+, +signing_secret_set+, +timeout_ms+, +last_call+.
      def get_before_user_create
        request(method: :get, path: "/v1/instance/hooks/before_user_create")
      end

      # Partial update: +enabled+, +url+, +signing_secret+ (+nil+ clears) and
      # +timeout_ms+ (500-5000). Turning it on needs +url+ and +signing_secret+.
      def update_before_user_create(body, idempotency_key: nil)
        request(method: :patch, path: "/v1/instance/hooks/before_user_create", body: body, idempotency_key: idempotency_key)
      end

      # Send the hook a sample draft and return its answer (+ok+, +latency_ms+,
      # +answer+, +error+); nothing is stored.
      def test_before_user_create
        request(method: :post, path: "/v1/instance/hooks/before_user_create/test")
      end

      # The hook's delivery log, newest first (kept 30 days). +params+: +limit+,
      # +status+ (+ok+, +failed+, +timeout+, +error+, +invalid_response+), +test+
      # and +starting_after+.
      def list_before_user_create_calls(params = {})
        request(method: :get, path: "/v1/instance/hooks/before_user_create/calls", query: params.empty? ? nil : params)
      end
    end
  end
end
