# frozen_string_literal: true

require_relative "test_helper"

# Test and review accounts, verified domains, and the new error codes.
class R4ProvisionedAccountsTest < Minitest::Test
  PASSWORD = "hunter2-hunter2-hunter2"

  def client
    http = Atlas::Test::StubRequester.new
    [Atlas::Client.new("psk_test_1", http: http), http]
  end

  def accounts(c) = c.platform.atlas_id_apps.provisioned_accounts

  def test_create_returns_password_once
    c, http = client
    http.enqueue(body: { "id" => "pa_1", "password" => PASSWORD })
    res = accounts(c).create("app_1", { email: "r@example.com", label: "reviewer" })
    assert_equal PASSWORD, res["password"]
    refute http.last.headers.key?("x-secret-recipient")
  end

  def test_sealed_password_path_sends_recipient_and_holds_no_plaintext
    c, http = client
    http.enqueue(body: { "id" => "pa_1", "sealed_password" => "sealedbytes" })
    res = accounts(c).create("app_1", { email: "r@example.com", label: "reviewer" },
                             secret_recipient: "x25519:AAAA")
    assert_equal "x25519:AAAA", http.last.headers["x-secret-recipient"]
    assert_equal "sealedbytes", res["sealed_password"]
    refute res.key?("password")
    refute_includes res.inspect, PASSWORD
    refute_includes http.last.body, PASSWORD

    http.enqueue(body: { "id" => "pa_1", "sealed_password" => "s2" })
    accounts(c).rotate_password("app_1", "pa_1", secret_recipient: "x25519:BBBB")
    assert_equal "x25519:BBBB", http.last.headers["x-secret-recipient"]
    assert_nil http.last.body
  end

  def test_domains_verify_alias
    c, http = client
    http.enqueue(body: {})
    c.platform.domains.verify("dom_1")
    assert_equal "https://api.atlasauth.net/v1/platform/domains/dom_1/verify", http.last.url
  end

  def test_error_codes
    assert_equal "TEST_ACCOUNT_RESTRICTED", Atlas::ErrorCode::TEST_ACCOUNT_RESTRICTED
    assert_equal "PROVISIONED_ACCOUNT_LIMIT_REACHED", Atlas::ErrorCode::PROVISIONED_ACCOUNT_LIMIT_REACHED
    assert_equal "DOMAIN_NOT_VERIFIED", Atlas::ErrorCode::DOMAIN_NOT_VERIFIED
  end
end
