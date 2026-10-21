# frozen_string_literal: true

require_relative "test_helper"

# Referral attribution: the instance settings, connection test and call log, and
# the user referral fields and fraud flag.
class ReferralsTest < Minitest::Test
  BASE = "https://api.atlasauth.net"
  SETTINGS = {
    "object" => "referral_settings", "enabled" => true, "provider" => "webhook",
    "endpoint_url" => "https://referrals.example.com/atlas", "signing_secret_set" => true, "api_key_set" => false,
    "url_params" => %w[ref via aff], "auto_enroll_users" => true, "timeout_ms" => 3000,
    "security" => { "challenge_referred_signups" => "always", "on_high_risk" => "flag",
                    "hold_until_email_verified" => false, "max_referred_signups_per_ip_hour" => 5 },
    "providers" => [{ "id" => "webhook", "capabilities" => { "signal" => true }, "needs" => %w[endpoint_url signing_secret] }]
  }.freeze
  CALL = { "object" => "referral_call", "id" => "rfc_1", "kind" => "signup", "status" => "succeeded",
           "outcome" => "referred", "customer_ref" => "user_1", "attempts" => 2,
           "risk" => { "level" => "low", "score" => 5, "signals" => [], "captcha" => "passed", "emailVerified" => true } }.freeze

  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
  end

  def test_settings_get_update_and_test
    @http.enqueue(body: SETTINGS)
    assert_equal "flag", @client.referrals.get["security"]["on_high_risk"]
    assert_equal ["GET", "#{BASE}/v1/instance/referrals"], [@http.last.method, @http.last.url]

    @http.enqueue(body: SETTINGS)
    @client.referrals.update({ enabled: true, link_template: nil, security: { on_high_risk: "hold" } }, idempotency_key: "idem_1")
    assert_equal "PATCH", @http.last.method
    assert_equal({ "enabled" => true, "link_template" => nil, "security" => { "on_high_risk" => "hold" } }, JSON.parse(@http.last.body))
    assert_equal "idem_1", @http.last.headers["idempotency-key"]

    @http.enqueue(body: { "ok" => false, "http_status" => 401, "error" => { "code" => "signature_rejected", "message" => "m" } })
    assert_equal "signature_rejected", @client.referrals.test["error"]["code"]
    assert_equal ["POST", "#{BASE}/v1/instance/referrals/test"], [@http.last.method, @http.last.url]
  end

  def test_call_log_and_retry
    @http.enqueue(body: { "object" => "list", "data" => [CALL], "has_more" => false })
    page = @client.referrals.list_calls(limit: 10, status: "failed", kind: "signup", user_id: "user_1")
    assert_equal true, page["data"][0]["risk"]["emailVerified"]
    assert_equal "#{BASE}/v1/instance/referrals/calls?limit=10&status=failed&kind=signup&user_id=user_1", @http.last.url

    @http.enqueue(body: { "object" => "list", "data" => [] })
    @client.referrals.list_calls
    assert_equal "#{BASE}/v1/instance/referrals/calls", @http.last.url

    @http.enqueue(body: CALL)
    assert_equal "referred", @client.referrals.retry_call("rfc_1", idempotency_key: "idem_2")["outcome"]
    assert_equal ["POST", "#{BASE}/v1/instance/referrals/calls/rfc_1/retry"], [@http.last.method, @http.last.url]
    assert_equal "idem_2", @http.last.headers["idempotency-key"]
  end

  def test_user_referral_fields_and_flag
    user = { "object" => "user", "id" => "user_1",
             "referral" => { "partner_id" => "pn_1", "referrer_external_id" => "cust_9", "referrer_user_id" => "user_9",
                             "matched_via" => "code", "status" => "lead", "risk_level" => "low", "flagged" => false },
             "referral_code" => "ada-1", "referral_link" => "https://app.example.com/join?ref=ada-1" }
    @http.enqueue(body: user)
    created = @client.users.create({ email_address: "a@example.com", referral: { code: "ACME10", click_id: "clk_123" }, referral_code: "ada-1" })
    assert_equal "user_9", created["referral"]["referrer_user_id"]
    assert_equal({ "email_address" => "a@example.com", "referral" => { "code" => "ACME10", "click_id" => "clk_123" }, "referral_code" => "ada-1" },
                 JSON.parse(@http.last.body))

    @http.enqueue(body: user)
    @client.users.update("user_1", { referral_code: nil })
    assert_equal({ "referral_code" => nil }, JSON.parse(@http.last.body))

    @http.enqueue(body: { "object" => "user_referral", "user_id" => "user_1", "status" => "flagged", "flagged" => true })
    assert @client.users.flag_referral("user_1", reason: "ring", idempotency_key: "idem_3")["flagged"]
    assert_equal ["POST", "#{BASE}/v1/users/user_1/referral/flag"], [@http.last.method, @http.last.url]
    assert_equal({ "reason" => "ring" }, JSON.parse(@http.last.body))
    assert_equal "idem_3", @http.last.headers["idempotency-key"]

    @http.enqueue(body: { "object" => "user_referral" })
    @client.users.flag_referral("user_1")
    assert_equal({}, JSON.parse(@http.last.body))
  end

  def test_referral_error_codes
    @http.enqueue(status: 409, body: { "errors" => [{ "code" => "REFERRAL_CODE_TAKEN", "message" => "taken", "param" => "referral_code" }] })
    err = assert_raises(Atlas::APIError) { @client.users.update("user_1", { referral_code: "ada-1" }) }
    assert_equal 409, err.status
    assert_equal Atlas::ErrorCode::REFERRAL_CODE_TAKEN, err.code
    assert_equal "REFERRALS_NOT_CONFIGURED", Atlas::ErrorCode::REFERRALS_NOT_CONFIGURED
  end
end
