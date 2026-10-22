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

  def test_inbound_two_way_sync_fields
    inbound = { "url" => "https://api.example.test/v1/webhooks/referrals/ins_1", "secret_set" => true, "endpoint_id" => "we_1",
                "last_event" => { "at" => 1_700_000_000_000, "type" => "referral.updated", "outcome" => "applied" } }
    @http.enqueue(body: SETTINGS.merge("inbound" => inbound))
    view = @client.referrals.get
    assert_equal "https://api.example.test/v1/webhooks/referrals/ins_1", view["inbound"]["url"]
    assert_equal "applied", view["inbound"]["last_event"]["outcome"]

    @http.enqueue(body: SETTINGS)
    @client.referrals.update({ inbound_secret: "whsec_#{"y" * 32}", inbound_endpoint_id: "we_1" })
    assert_equal({ "inbound_secret" => "whsec_#{"y" * 32}", "inbound_endpoint_id" => "we_1" }, JSON.parse(@http.last.body))

    @http.enqueue(body: SETTINGS)
    @client.referrals.update({ inbound_secret: nil, inbound_endpoint_id: nil })
    assert_equal({ "inbound_secret" => nil, "inbound_endpoint_id" => nil }, JSON.parse(@http.last.body))
  end

  def test_browser_capture_fields
    @http.enqueue(body: SETTINGS.merge("browser_sources" => %w[rewardful dub], "browser_sources_default" => false, "consent_provider" => "onetrust"))
    view = @client.referrals.get
    assert_equal %w[rewardful dub], view["browser_sources"]
    assert_equal false, view["browser_sources_default"]
    assert_equal "onetrust", view["consent_provider"]

    @http.enqueue(body: SETTINGS)
    @client.referrals.update({ browser_sources: %w[rewardful dub], consent_provider: "app" })
    assert_equal({ "browser_sources" => %w[rewardful dub], "consent_provider" => "app" }, JSON.parse(@http.last.body))

    @http.enqueue(body: SETTINGS)
    @client.referrals.update({ browser_sources: nil })
    assert_equal({ "browser_sources" => nil }, JSON.parse(@http.last.body))
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
  def test_v2_settings_fields_ping_test_and_call_paging
    settings = SETTINGS.merge("provider" => "referally", "tracking_token" => "tt_public_1", "signup_code_field" => true,
                              "include_referral_claims" => true,
                              "connection" => { "last_ping" => { "ok" => true, "org_name" => "Acme", "clock_skew_warning" => true },
                                                "alert" => { "code" => "signature_rejected", "message" => "401", "at" => 9 } })
    @http.enqueue(body: settings)
    view = @client.referrals.get
    assert_equal "tt_public_1", view["tracking_token"]
    assert_equal "signature_rejected", view["connection"]["alert"]["code"]

    @http.enqueue(body: settings)
    @client.referrals.update({ provider: "referally", tracking_token: "tt_public_1", code_lookup_url: nil,
                               forward_lifecycle: false, mirror_to_public_metadata: true, include_referral_claims: true })
    assert_equal({ "provider" => "referally", "tracking_token" => "tt_public_1", "code_lookup_url" => nil,
                   "forward_lifecycle" => false, "mirror_to_public_metadata" => true, "include_referral_claims" => true },
                 JSON.parse(@http.last.body))

    @http.enqueue(body: { "ok" => true, "method" => "ping", "ping" => { "ok" => true, "org_name" => "Acme" }, "warnings" => ["clock skew"] })
    tested = @client.referrals.test
    assert_equal %w[ping Acme], [tested["method"], tested["ping"]["org_name"]]

    @http.enqueue(body: { "object" => "list", "data" => [CALL.merge("error_code" => "signature_rejected", "batch_id" => "rbf_1")], "has_more" => true })
    page = @client.referrals.list_calls(limit: 1000, error_code: "signature_rejected", starting_after: "rfc_0")
    assert_equal "#{BASE}/v1/instance/referrals/calls?limit=1000&error_code=signature_rejected&starting_after=rfc_0", @http.last.url
    assert_equal "rbf_1", page["data"][0]["batch_id"]
  end

  def test_v2_retry_failed_simulate_backfill_and_user_result
    @http.enqueue(body: { "object" => "referral_retry", "requeued" => 4 })
    assert_equal 4, @client.referrals.retry_failed({ error_code: "signature_rejected" }, idempotency_key: "k1")["requeued"]
    assert_equal ["POST", "#{BASE}/v1/instance/referrals/calls/retry_failed"], [@http.last.method, @http.last.url]
    assert_equal({ "error_code" => "signature_rejected" }, JSON.parse(@http.last.body))
    assert_equal "k1", @http.last.headers["idempotency-key"]

    @http.enqueue(body: { "object" => "referral_simulation", "ok" => true, "customer_ref" => "atlas_test_abc",
                          "result" => { "referral" => { "partner_external_ref" => "cust_9" }, "partner" => nil, "notes" => ["n"] } })
    sim = @client.referrals.simulate(code: "ACME10")
    assert_equal "cust_9", sim["result"]["referral"]["partner_external_ref"]
    assert_equal ["POST", "#{BASE}/v1/instance/referrals/simulate"], [@http.last.method, @http.last.url]
    assert_equal({ "code" => "ACME10" }, JSON.parse(@http.last.body))
    @http.enqueue(body: { "object" => "referral_simulation", "ok" => false })
    @client.referrals.simulate
    assert_equal({}, JSON.parse(@http.last.body))

    job = { "object" => "referral_backfill", "id" => "rbf_1", "status" => "running", "calls" => { "pending" => 10 } }
    @http.enqueue(body: job)
    out = @client.referrals.backfill({ since: "2026-01-01", codes: { "cust_1" => "ACME10" } }, idempotency_key: "k2")
    assert_equal 10, out["calls"]["pending"]
    assert_equal ["POST", "#{BASE}/v1/instance/referrals/backfill"], [@http.last.method, @http.last.url]
    assert_equal({ "since" => "2026-01-01", "codes" => { "cust_1" => "ACME10" } }, JSON.parse(@http.last.body))
    @http.enqueue(body: job.merge("status" => "completed"))
    assert_equal "completed", @client.referrals.get_backfill("rbf_1")["status"]
    assert_equal ["GET", "#{BASE}/v1/instance/referrals/backfill/rbf_1"], [@http.last.method, @http.last.url]

    @http.enqueue(body: { "object" => "user_referral", "user_id" => "user_1", "status" => "attributed", "customer_ref" => "cust_1",
                          "referral_status" => "active", "notes" => ["n"] })
    res = @client.referrals.get_for_user("user_1")
    assert_equal %w[attributed active], [res["status"], res["referral_status"]]
    assert_equal ["GET", "#{BASE}/v1/users/user_1/referral"], [@http.last.method, @http.last.url]
  end

  def test_v2_set_external_id_and_before_user_create_hook
    @http.enqueue(body: { "object" => "user", "id" => "user_1", "external_id" => "cust_1", "referral" => { "status" => "pending" } })
    assert_equal "pending", @client.users.set_external_id("user_1", "cust_1")["referral"]["status"]
    assert_equal ["PATCH", "#{BASE}/v1/users/user_1"], [@http.last.method, @http.last.url]
    assert_equal({ "external_id" => "cust_1" }, JSON.parse(@http.last.body))
    @http.enqueue(body: { "object" => "user", "id" => "user_1" })
    @client.users.set_external_id("user_1", nil)
    assert_equal({ "external_id" => nil }, JSON.parse(@http.last.body))

    hook = { "object" => "before_user_create_hook", "enabled" => true, "url" => "https://app.example.com/hooks/before-create",
             "signing_secret_set" => true, "timeout_ms" => 3000, "last_call" => { "at" => 3, "status" => "ok", "error" => nil } }
    @http.enqueue(body: hook)
    assert_equal "ok", @client.user_hooks.get_before_user_create["last_call"]["status"]
    assert_equal ["GET", "#{BASE}/v1/instance/hooks/before_user_create"], [@http.last.method, @http.last.url]
    @http.enqueue(body: hook)
    @client.user_hooks.update_before_user_create({ enabled: true, signing_secret: "s" * 32, timeout_ms: 2000 }, idempotency_key: "k3")
    assert_equal ["PATCH", "#{BASE}/v1/instance/hooks/before_user_create"], [@http.last.method, @http.last.url]
    assert_equal({ "enabled" => true, "signing_secret" => "s" * 32, "timeout_ms" => 2000 }, JSON.parse(@http.last.body))
    assert_equal "k3", @http.last.headers["idempotency-key"]
    @http.enqueue(body: { "ok" => true, "latency_ms" => 12, "answer" => { "external_id" => "cust_1" } })
    assert_equal "cust_1", @client.user_hooks.test_before_user_create["answer"]["external_id"]
    assert_equal ["POST", "#{BASE}/v1/instance/hooks/before_user_create/test"], [@http.last.method, @http.last.url]
  end
end
