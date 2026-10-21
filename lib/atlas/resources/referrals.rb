# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance/referrals+ — referral attribution: the instance's connection
    # to a referral platform, the connection test and the call log.
    #
    # With referrals on, every interactive sign-up is reported to the platform
    # before +user.created+ is sent; the answer lands on the user (+referral+,
    # +referral_code+, +referral_link+). A late answer arrives as the
    # +user.referral_attributed+ webhook. +signing_secret+ and +api_key+ are
    # write-only: reads return +signing_secret_set+ / +api_key_set+.
    class Referrals < Base
      # The settings, the connection status (+connection+) and the supported
      # +providers+ (with their +capabilities+ and +needs+).
      def get
        request(method: :get, path: "/v1/instance/referrals")
      end

      # Partial update: only the keys sent change, +nil+ clears. +security+ is
      # partial too (+challenge_referred_signups+, +on_high_risk+,
      # +hold_until_email_verified+, +max_referred_signups_per_ip_hour+).
      # Enabling without what the provider needs is 422 +REFERRALS_NOT_CONFIGURED+.
      #
      #   atlas.referrals.update({ enabled: true, endpoint_url: "https://referrals.example.com/atlas",
      #                            signing_secret: ENV["REFERRAL_SIGNING_SECRET"] })
      def update(body, idempotency_key: nil)
        request(method: :patch, path: "/v1/instance/referrals", body: body, idempotency_key: idempotency_key)
      end

      # A signed probe of the platform: +ok+ on 2xx or 404; +error.code+
      # +signature_rejected+ on 401/403.
      def test
        request(method: :post, path: "/v1/instance/referrals/test")
      end

      # The call log, newest first. +params+: +limit+ (1-200, default 50),
      # +status+, +kind+, +user_id+.
      def list_calls(params = {})
        request(method: :get, path: "/v1/instance/referrals/calls", query: params.empty? ? nil : params)
      end

      # Retry a failed, retrying or skipped call now (not a connection test).
      def retry_call(id, idempotency_key: nil)
        request(method: :post, path: "/v1/instance/referrals/calls/#{enc(id)}/retry", idempotency_key: idempotency_key)
      end
    end
  end
end
