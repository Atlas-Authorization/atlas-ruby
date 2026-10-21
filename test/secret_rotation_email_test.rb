# frozen_string_literal: true

require_relative "test_helper"

# OAuth client secret rotation with overlap, the development email sender,
# managed email on your own provider account, origin integrations and the new
# error codes.
class SecretRotationEmailTest < Minitest::Test
  BASE = "https://api.atlasauth.net"

  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
  end

  def test_rotate_secret_sends_overlap_and_returns_the_expiry
    @http.enqueue(body: { "object" => "oauth_client", "id" => "oc_1", "client_secret" => "cs_new",
                          "overlap_seconds" => 0, "previous_secret_expires_at" => nil })
    out = @client.oauth_clients.rotate_secret("oc_1", { overlap_seconds: 0 }, idempotency_key: "idem_1")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "#{BASE}/v1/oauth_clients/oc_1/rotate_secret", req.url
    assert_equal({ "overlap_seconds" => 0 }, JSON.parse(req.body))
    assert_equal "idem_1", req.headers["idempotency-key"]
    assert_equal "cs_new", out["client_secret"]
    assert_nil out["previous_secret_expires_at"]

    @http.enqueue(body: { "object" => "oauth_client", "id" => "oc_1", "overlap_seconds" => 86_400 })
    @client.oauth_clients.rotate_secret("oc_1")
    assert_nil @http.last.body
  end

  def test_development_email_get_enable_disable
    dev = { "object" => "development_email", "provider_id" => "mp_1", "enabled" => true, "active" => true,
            "transport" => "resend", "from_address" => "onboarding@resend.dev", "subject_prefix" => "[Atlas test] ",
            "limits" => { "daily" => 100, "per_recipient_hourly" => 10 } }
    @http.enqueue(body: dev)
    assert_equal 10, @client.messaging.get_development_email["limits"]["per_recipient_hourly"]
    assert_equal "GET", @http.last.method
    assert_equal "#{BASE}/v1/messaging_providers/email/development", @http.last.url

    @http.enqueue(status: 201, body: dev)
    @client.messaging.enable_development_email({ provider_id: "mp_1" })
    assert_equal "POST", @http.last.method
    assert_equal({ "provider_id" => "mp_1" }, JSON.parse(@http.last.body))

    @http.enqueue(body: { "object" => "development_email", "deleted" => true, "provider_id" => "mp_1", "mode" => "standard" })
    assert_equal "standard", @client.messaging.disable_development_email["mode"]
    assert_equal "DELETE", @http.last.method
    assert_equal "#{BASE}/v1/messaging_providers/email/development", @http.last.url
  end

  def test_managed_email_on_your_own_account
    @http.enqueue(status: 201, body: { "object" => "managed_email", "provider_id" => "mp_2", "limits" => nil,
                                       "reputation" => "your_provider_account", "feedback_webhook" => "registered" })
    out = @client.messaging.create_managed_email({ from_address: "hi@acme.example", transport: "brevo", config: { api_key: "xkeysib-x" } })
    assert_equal({ "from_address" => "hi@acme.example", "transport" => "brevo", "config" => { "api_key" => "xkeysib-x" } },
                 JSON.parse(@http.last.body))
    assert_nil out["limits"]
    assert_equal "mp_2", out["provider_id"]
  end

  def test_allowed_origins_accept_integration_objects
    @http.enqueue(body: { "object" => "instance", "allowed_origin_integrations" => { "https://app.example" => "redirect" } })
    out = @client.instance.update({ allowed_origins: ["https://a.example", { origin: "https://app.example", integration: "redirect" }] })
    assert_equal({ "allowed_origins" => ["https://a.example", { "origin" => "https://app.example", "integration" => "redirect" }] },
                 JSON.parse(@http.last.body))
    assert_equal "redirect", out["allowed_origin_integrations"]["https://app.example"]
  end

  def test_new_error_codes
    %w[READ_ONLY_FIELD DEVELOPMENT_EMAIL_NOT_ALLOWED DEVELOPMENT_EMAIL_UNAVAILABLE
       DEVELOPMENT_EMAIL_LIMIT_REACHED DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED].each do |code|
      assert_equal code, Atlas::ErrorCode.const_get(code)
    end
  end
end
