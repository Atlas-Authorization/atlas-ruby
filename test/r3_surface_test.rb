# frozen_string_literal: true

require_relative "test_helper"

# Partner platforms, per-call audiences, privacy orchestrator fields, include_deleted.
class R3SurfaceTest < Minitest::Test
  SECRET = "ptok_super_secret_value_123"

  def client(**opts)
    http = Atlas::Test::StubRequester.new
    [Atlas::Client.new("sk_test_1", http: http, **opts), http]
  end

  def test_per_call_audience_query
    c, http = client
    http.enqueue(body: { "jwt" => "x" })
    c.sessions.get_token("sess_1", for: "cookiemunch", cbid: "dv-1")
    assert_equal "https://api.atlasauth.net/v1/sessions/sess_1/integration_tokens/cookiemunch?cbid=dv-1", http.last.url
    http.enqueue(body: { "jwt" => "x" })
    c.integrations.get_token("sess_1", for: "acme", audience: "acme:t1", audience_params: { tenant: "t1" })
    assert_equal "https://api.atlasauth.net/v1/sessions/sess_1/integration_tokens/acme?tenant=t1&audience=acme%3At1", http.last.url
    http.enqueue(body: { "jwt" => "x" })
    c.sessions.get_token("sess_1", for: "chatly")
    assert_equal "https://api.atlasauth.net/v1/sessions/sess_1/integration_tokens/chatly", http.last.url
  end

  def test_per_call_audience_off_is_sent_as_null
    c, http = client
    http.enqueue(body: {})
    c.integrations.set("acme", { per_call_audience: nil })
    assert_equal({ "per_call_audience" => nil }, JSON.parse(http.last.body))
  end

  def test_orchestrator_fields_pass_through
    c, http = client
    http.enqueue(body: {})
    body = { provider: "acme-consent", site_id: "site-1", partner_link_id: "pl_1", cancel_deletion_on_sign_in: true }
    c.privacy.orchestrator.set(body)
    assert_equal "PUT", http.last.method
    assert_equal body.transform_keys(&:to_s), JSON.parse(http.last.body)
  end

  def test_users_include_deleted
    c, http = client
    http.enqueue(body: { "data" => [] })
    c.users.list(include_deleted: true)
    assert_equal "https://api.atlasauth.net/v1/users?include_deleted=true", http.last.url
    http.enqueue(body: {})
    c.users.get("usr_1", include_deleted: true)
    assert_equal "https://api.atlasauth.net/v1/users/usr_1?include_deleted=true", http.last.url
    http.enqueue(body: {})
    c.users.get("usr_1")
    assert_equal "https://api.atlasauth.net/v1/users/usr_1", http.last.url
  end

  def test_managed_waf_error_code
    assert_equal "MANAGED_WAF_NOT_CONFIGURED", Atlas::ErrorCode::MANAGED_WAF_NOT_CONFIGURED
  end

  def test_partner_token_never_echoed_or_inspected
    c, http = client
    http.enqueue(body: { "object" => "partner_platform", "partner" => "acme", "token_set" => true, "token_prefix" => "ptok_sup" })
    res = c.partner_platforms.store_token("acme", SECRET)
    assert_equal SECRET, JSON.parse(http.last.body)["token"]
    refute_includes res.inspect, SECRET
    refute res.key?("token")
    refute_includes c.partner_platforms.inspect, SECRET
    out, err = capture_io do
      http.enqueue(body: { "partner" => "acme" })
      c.partner_platforms.store_token("acme", SECRET, rotate: true)
    end
    refute_includes out + err, SECRET
  end
end
