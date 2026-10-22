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
    # +user.referral_resolved+ webhook (and +user.referral_attributed+ when it
    # attributes the user). +provider+ is +webhook+ (the Atlas referral
    # protocol), +referally+ or another built-in adapter. +signing_secret+ and
    # +api_key+ are write-only: reads return +signing_secret_set+ / +api_key_set+.
    class Referrals < Base
      # The settings, the connection status (+connection+) and the supported
      # +providers+ (with their +capabilities+ and +needs+).
      def get
        request(method: :get, path: "/v1/instance/referrals")
      end

      # Partial update: only the keys sent change, +nil+ clears. +security+ is
      # partial too (+challenge_referred_signups+, +on_high_risk+,
      # +hold_until_email_verified+, +max_referred_signups_per_ip_hour+). Also
      # +tracking_token+, +code_lookup_url+ (an https URL template with
      # +{code}+), +signup_code_field+, +forward_lifecycle+ (default true),
      # +mirror_to_public_metadata+ and +include_referral_claims+. Reads add
      # +connection.last_ping+ and +connection.alert+ (+signature_rejected+ or
      # +connection_paused+ while delivery is blocked).
      # Enabling without what the provider needs is 422 +REFERRALS_NOT_CONFIGURED+.
      #
      #   atlas.referrals.update({ enabled: true, endpoint_url: "https://referrals.example.com/atlas",
      #                            signing_secret: ENV["REFERRAL_SIGNING_SECRET"] })
      def update(body, idempotency_key: nil)
        request(method: :patch, path: "/v1/instance/referrals", body: body, idempotency_key: idempotency_key)
      end

      # Test the connection: a ping where the provider answers one (+method+
      # +ping+, with +ping+ and +warnings+ such as clock skew), else a signed
      # probe (+method+ +probe+: +ok+ on 2xx or 404). +error.code+ is
      # +signature_rejected+ on 401/403.
      def test
        request(method: :post, path: "/v1/instance/referrals/test")
      end

      # The call log, newest first. +params+: +limit+ (1-1000, default 50;
      # servers before referral attribution v2 take at most 200), +status+,
      # +kind+, +user_id+, +error_code+ and +starting_after+ (the id of the last
      # call of the previous page, while +has_more+). Calls carry +error_code+,
      # +latency_ms+, +request_id+, +response+, +highlights+ and +batch_id+.
      def list_calls(params = {})
        request(method: :get, path: "/v1/instance/referrals/calls", query: params.empty? ? nil : params)
      end

      # Retry a failed, retrying or skipped call now (not a connection test).
      def retry_call(id, idempotency_key: nil)
        request(method: :post, path: "/v1/instance/referrals/calls/#{enc(id)}/retry", idempotency_key: idempotency_key)
      end

      # Re-queue every failed call (not tests) to send now. +body+: +kind+,
      # +error_code+ (e.g. +signature_rejected+ after replacing the secret).
      # Returns +{ "object" => "referral_retry", "requeued" => n }+.
      def retry_failed(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/instance/referrals/calls/retry_failed", body: body, idempotency_key: idempotency_key)
      end

      # Send a sign-up call for a made-up user (+atlas_test_<random>+; no user
      # is created) with an optional +code+, and return what the platform
      # answered (+call_id+, +customer_ref+, +result+, +response+, +error+).
      def simulate(code: nil)
        body = {}
        body[:code] = code unless code.nil?
        request(method: :post, path: "/v1/instance/referrals/simulate", body: body)
      end

      # Queue sign-up calls for existing users created at or after +since+
      # (ISO 8601), with their real sign-up time. +body+: +since+, +codes+
      # (customerRef => code), +code_metadata_path+. Users already reported are
      # skipped. Returns the job; poll +get_backfill+.
      def backfill(body, idempotency_key: nil)
        request(method: :post, path: "/v1/instance/referrals/backfill", body: body, idempotency_key: idempotency_key)
      end

      # A backfill job: +status+ (+running+, then +completed+), +users_scanned+,
      # +users_skipped+, +calls_queued+, +truncated+, +next_since+, +calls+.
      def get_backfill(id)
        request(method: :get, path: "/v1/instance/referrals/backfill/#{enc(id)}")
      end

      # +GET /v1/users/:id/referral+ — the stored result for one user (+status+,
      # +customer_ref+, +partner_external_ref+, +referral_status+, +notes+, ...),
      # with no call to the platform. 404 when the user was never reported.
      def get_for_user(user_id)
        request(method: :get, path: "/v1/users/#{enc(user_id)}/referral")
      end
    end
  end
end
