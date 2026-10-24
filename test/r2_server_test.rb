# frozen_string_literal: true

require_relative "test_helper"

# Round-2 server surface: adoption, instance app preflight, dry-run result, sealed recipient.
class R2ServerTest < Minitest::Test
  def client(**opts)
    http = Atlas::Test::StubRequester.new
    [Atlas::Client.new("psk_test_1", http: http, **opts), http]
  end

  def test_set_managed_by
    c, http = client
    http.enqueue(body: { "changed" => true, "managed_via" => "adopted" })
    res = c.platform.atlas_id_apps.set_managed_by("app_1", "ins_1")
    assert_equal "PUT", http.last.method
    assert_equal "https://api.atlasauth.net/v1/platform/atlas_id_apps/app_1/managed_by", http.last.url
    assert_equal({ "instance_id" => "ins_1" }, JSON.parse(http.last.body))
    assert_equal "adopted", res["managed_via"]
    http.enqueue(body: { "changed" => true })
    c.platform.atlas_id_apps.set_managed_by("app_1", nil)
    assert_equal({ "instance_id" => nil }, JSON.parse(http.last.body))
  end

  def test_instance_preflight
    c, http = client
    http.enqueue(body: { "ok" => true })
    c.atlas_id_apps.preflight("app_1")
    assert_equal "GET", http.last.method
    assert_equal "https://api.atlasauth.net/v1/atlas_id_apps/app_1/preflight", http.last.url
  end

  def test_secret_recipient_header
    c, http = client(secret_recipient: "x25519:abc")
    http.enqueue(body: {})
    c.whoami.get
    assert_equal "x25519:abc", http.last.headers["x-secret-recipient"]
    http.enqueue(body: {})
    c.with_options(secret_recipient: nil).whoami.get
    refute http.last.headers.key?("x-secret-recipient")
    http.enqueue(body: {})
    c.with_options(strict: true).whoami.get
    assert_equal "x25519:abc", http.last.headers["x-secret-recipient"]
  end

  def test_dry_run_result
    r = Atlas::DryRunResult.from(
      "mode" => "rollback", "validated" => true, "would_return_status" => 201, "suppressed" => ["email"],
      "warnings" => [{ "code" => "origin_still_referenced" }], "validation_skipped" => nil
    )
    assert_equal "rollback", r.mode
    assert r.validated?
    assert_equal 201, r.would_return_status
    assert_equal ["email"], r.suppressed
    plan = Atlas::DryRunResult.from("mode" => "plan", "validated" => false,
                                    "validation_skipped" => { "reason" => "external_call", "detail" => "d" })
    refute plan.validated?
    assert_equal "external_call", plan.validation_skipped["reason"]
  end

  def test_sso_claims
    sso = Atlas::OIDC.sso_of("sso_connection_id" => "s", "sso_organization_id" => "o", "sso_connection_type" => "ldap")
    assert_equal "o", sso[:organization_id]
    assert_nil sso[:type]
  end
end
