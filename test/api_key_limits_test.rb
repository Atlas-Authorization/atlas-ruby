# frozen_string_literal: true

require_relative "test_helper"

# API key spend caps (limits + usage metering), session keep-alive and the
# explicit notify flag on user create/import.
class ApiKeyLimitsTest < Minitest::Test
  LIMITS = [
    { "unit" => "requests", "amount" => 1000, "period" => "day" },
    { "unit" => "usd_cents", "amount" => 500, "period" => "request" }
  ].freeze

  STATE = {
    "unit" => "requests", "period" => "day", "amount" => 1000, "used" => 10, "remaining" => 990,
    "window_start" => 1_760_400_000_000, "resets_at" => 1_760_486_400_000
  }.freeze

  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
  end

  def test_create_sends_limits
    @http.enqueue(status: 201, body: { "object" => "api_key", "id" => "ak_1", "limits" => LIMITS, "usage" => [STATE] })
    key = @client.api_keys.create({ subject_type: "user", subject_id: "user_1", limits: LIMITS })

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/api_keys", req.url
    assert_equal LIMITS, JSON.parse(req.body)["limits"]
    assert_equal 990, key["usage"][0]["remaining"]
  end

  def test_update_can_clear_limits_with_null
    @http.enqueue(body: { "object" => "api_key", "id" => "ak_1", "limits" => nil, "usage" => [] })
    @client.api_keys.update("ak_1", { limits: nil })

    req = @http.last
    assert_equal "PATCH", req.method
    assert_equal "https://api.atlasauth.net/v1/api_keys/ak_1", req.url
    assert_equal({ "limits" => nil }, JSON.parse(req.body))
  end

  def test_record_usage_posts_amount_unit_and_body_idempotency_key
    @http.enqueue(body: {
      "object" => "api_key_usage_debit", "key_id" => "ak_1", "unit" => "requests", "amount" => 1,
      "allowed" => true, "exceeded" => [], "usage" => [STATE],
      "counters" => [{ "unit" => "requests", "period" => "day", "used" => 11, "window_start" => 1, "resets_at" => 2 }],
      "idempotent_replay" => false
    })
    debit = @client.api_keys.record_usage("ak_1", amount: 1, unit: "requests", idempotency_key: "req_42")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/api_keys/ak_1/usage", req.url
    assert_equal({ "amount" => 1, "unit" => "requests", "idempotency_key" => "req_42" }, JSON.parse(req.body))
    refute req.headers.key?("idempotency-key"), "the idempotency key travels in the body"
    assert_equal true, debit["allowed"]
    assert_equal 11, debit["counters"][0]["used"]
  end

  def test_record_usage_omits_an_absent_idempotency_key_and_surfaces_a_refusal
    @http.enqueue(body: {
      "object" => "api_key_usage_debit", "key_id" => "ak_1", "unit" => "usd_cents", "amount" => 900,
      "allowed" => false, "code" => "LIMIT_EXCEEDED", "exceeded" => [STATE], "usage" => [STATE],
      "counters" => [], "idempotent_replay" => false
    })
    debit = @client.api_keys.record_usage("ak_1", amount: 900, unit: "usd_cents")

    assert_equal({ "amount" => 900, "unit" => "usd_cents" }, JSON.parse(@http.last.body))
    assert_equal false, debit["allowed"]
    assert_equal Atlas::ErrorCode::LIMIT_EXCEEDED, debit["code"]
  end

  def test_record_usage_idempotency_conflict_raises_conflict
    @http.enqueue(status: 409, body: { "errors" => [{ "code" => "IDEMPOTENCY_CONFLICT", "message" => "reused" }] })
    err = assert_raises(Atlas::ConflictError) do
      @client.api_keys.record_usage("ak_1", amount: 2, unit: "requests", idempotency_key: "req_42")
    end
    assert err.has_code?(Atlas::ErrorCode::IDEMPOTENCY_CONFLICT)
  end

  def test_get_usage
    @http.enqueue(body: { "object" => "api_key_usage", "key_id" => "ak_1", "limits" => LIMITS, "usage" => [STATE], "counters" => [] })
    usage = @client.api_keys.get_usage("ak_1")

    req = @http.last
    assert_equal "GET", req.method
    assert_equal "https://api.atlasauth.net/v1/api_keys/ak_1/usage", req.url
    assert_nil req.body
    assert_equal "api_key_usage", usage["object"]
    assert_equal LIMITS, usage["limits"]
  end

  def test_verify_returns_name_scopes_limits_and_usage
    @http.enqueue(body: {
      "valid" => true, "id" => "ak_1", "name" => "CI", "scopes" => ["read"], "constraints" => {},
      "limits" => LIMITS, "usage" => [STATE]
    })
    result = @client.api_keys.verify("ak_secret")
    assert_equal "CI", result["name"]
    assert_equal ["read"], result["scopes"]
    assert_equal "requests", result["usage"][0]["unit"]
  end

  def test_session_touch
    @http.enqueue(body: { "object" => "session", "id" => "sess_1", "idle_expires_at" => 1_760_486_400_000, "extended" => true })
    session = @client.sessions.touch("sess_1")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/sessions/sess_1/touch", req.url
    assert_nil req.body
    assert_equal true, session["extended"]
    assert_equal 1_760_486_400_000, session["idle_expires_at"]
  end

  def test_session_touch_on_an_ended_session_raises_conflict
    @http.enqueue(status: 409, body: { "errors" => [{ "code" => "SESSION_IDLE_EXPIRED", "message" => "ended" }] })
    err = assert_raises(Atlas::ConflictError) { @client.sessions.touch("sess_1") }
    assert err.has_code?(Atlas::ErrorCode::SESSION_IDLE_EXPIRED)
  end

  def test_users_create_and_import_send_notify
    @http.enqueue(status: 201, body: { "id" => "user_1" })
    @client.users.create({ email_address: ["ada@example.com"], notify: false })
    assert_equal false, JSON.parse(@http.last.body)["notify"]

    @http.enqueue(status: 202, body: { "id" => "job_1" })
    @client.import_export.import_users({ users: [], notify: false })
    assert_equal "https://api.atlasauth.net/v1/user_imports", @http.last.url
    assert_equal false, JSON.parse(@http.last.body)["notify"]
  end
end
