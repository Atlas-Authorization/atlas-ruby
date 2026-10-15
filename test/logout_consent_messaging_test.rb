# frozen_string_literal: true

require_relative "test_helper"

# OAuth client skip_logout_confirmation, the cookie-consent settings link,
# forced messaging-provider removal and the users/{id}/sessions item fields.
class LogoutConsentMessagingTest < Minitest::Test
  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
  end

  def test_oauth_client_create_and_update_send_skip_logout_confirmation
    @http.enqueue(status: 201, body: { "object" => "oauth_client", "id" => "oc_1", "skip_logout_confirmation" => true })
    created = @client.oauth_clients.create({ name: "Portal", first_party: true, skip_logout_confirmation: true })

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/oauth_clients", req.url
    assert_equal true, JSON.parse(req.body)["skip_logout_confirmation"]
    assert_equal true, created["skip_logout_confirmation"]

    @http.enqueue(body: { "object" => "oauth_client", "id" => "oc_1", "skip_logout_confirmation" => false })
    updated = @client.oauth_clients.update("oc_1", { skip_logout_confirmation: false })

    req = @http.last
    assert_equal "PATCH", req.method
    assert_equal "https://api.atlasauth.net/v1/oauth_clients/oc_1", req.url
    assert_equal({ "skip_logout_confirmation" => false }, JSON.parse(req.body))
    assert_equal false, updated["skip_logout_confirmation"]
  end

  def test_oauth_client_skip_logout_confirmation_on_a_third_party_client_raises_unprocessable
    @http.enqueue(status: 422, body: { "errors" => [{ "code" => "VALIDATION_FAILED", "message" => "first-party only",
                                                      "param" => "skip_logout_confirmation" }] })
    err = assert_raises(Atlas::UnprocessableEntityError) do
      @client.oauth_clients.update("oc_3p", { skip_logout_confirmation: true })
    end
    assert err.has_code?(Atlas::ErrorCode::VALIDATION_FAILED)
    assert_equal "skip_logout_confirmation", err.errors.first["param"]
  end

  def test_cookie_consent_settings_link_round_trip
    link = { label: "Cookie settings", preset: "cookiebot", attributes: { "class" => "footer-link" } }
    @http.enqueue(body: {
      "object" => "cookie_consent", "enabled" => true, "script_url" => "https://consent.cookiebot.com/uc.js",
      "settings_link" => {
        "label" => "Cookie settings", "preset" => "cookiebot", "attributes" => { "class" => "footer-link" },
        "rendered_attributes" => { "class" => "footer-link", "href" => "javascript:Cookiebot.renew()" }
      }
    })
    consent = @client.instance.set_cookie_consent({ script_url: "https://consent.cookiebot.com/uc.js", settings_link: link })

    req = @http.last
    assert_equal "PUT", req.method
    assert_equal "https://api.atlasauth.net/v1/instance/cookie_consent", req.url
    assert_equal({ "label" => "Cookie settings", "preset" => "cookiebot", "attributes" => { "class" => "footer-link" } },
                 JSON.parse(req.body)["settings_link"])
    assert_equal "cookiebot", consent["settings_link"]["preset"]
    assert_equal "javascript:Cookiebot.renew()", consent["settings_link"]["rendered_attributes"]["href"]
    assert_equal %w[cookiemunch cookiebot onetrust custom], Atlas::Resources::Instance::COOKIE_CONSENT_PRESETS
  end

  def test_cookie_consent_settings_link_null_and_unknown_preset
    @http.enqueue(body: { "object" => "cookie_consent", "enabled" => true, "settings_link" => nil })
    consent = @client.instance.set_cookie_consent({ script_url: "https://cmp.example/s.js", settings_link: nil })
    assert_equal({ "script_url" => "https://cmp.example/s.js", "settings_link" => nil }, JSON.parse(@http.last.body))
    assert_nil consent["settings_link"]

    @http.enqueue(body: {
      "object" => "cookie_consent", "enabled" => true,
      "settings_link" => { "label" => "Privacy", "preset" => "future_cmp", "attributes" => {}, "rendered_attributes" => {} }
    })
    assert_equal "future_cmp", @client.instance.get_cookie_consent["settings_link"]["preset"]
  end

  def test_messaging_delete_channel_without_force_sends_no_query
    @http.enqueue(body: { "object" => "messaging_provider", "channel" => "email", "deleted" => true })
    result = @client.messaging.delete_channel("email")

    req = @http.last
    assert_equal "DELETE", req.method
    assert_equal "https://api.atlasauth.net/v1/messaging_providers/email", req.url
    assert_nil req.body
    assert_equal true, result["deleted"]

    @http.enqueue(body: { "object" => "messaging_provider", "channel" => "sms", "deleted" => true })
    @client.messaging.delete_channel("sms", force: false)
    assert_equal "https://api.atlasauth.net/v1/messaging_providers/sms", @http.last.url
  end

  def test_messaging_delete_channel_with_force
    @http.enqueue(body: { "object" => "messaging_provider", "channel" => "email", "deleted" => true })
    result = @client.messaging.delete_channel("email", force: true)

    req = @http.last
    assert_equal "DELETE", req.method
    assert_equal "https://api.atlasauth.net/v1/messaging_providers/email?force=true", req.url
    assert_equal "messaging_provider", result["object"]
    assert_equal "email", result["channel"]
  end

  def test_messaging_delete_email_provider_in_use_raises_conflict
    @http.enqueue(status: 409, body: { "errors" => [{
      "code" => "EMAIL_PROVIDER_IN_USE", "message" => "in use",
      "meta" => { "features" => %w[emailCode passwordReset] }
    }] })
    err = assert_raises(Atlas::ConflictError) { @client.messaging.delete_channel("email") }
    assert err.has_code?(Atlas::ErrorCode::EMAIL_PROVIDER_IN_USE)
    assert_equal %w[emailCode passwordReset], err.errors.first["meta"]["features"]
  end

  def test_email_provider_error_code_constants
    assert_equal "EMAIL_PROVIDER_IN_USE", Atlas::ErrorCode::EMAIL_PROVIDER_IN_USE
    assert_equal "EMAIL_PROVIDER_REQUIRED", Atlas::ErrorCode::EMAIL_PROVIDER_REQUIRED
  end

  def test_user_sessions_carry_idle_expiry_organization_and_impersonator
    @http.enqueue(body: { "object" => "list", "data" => [{
      "object" => "session", "id" => "sess_1", "user_id" => "user_1", "status" => "active",
      "abandon_at" => 1_760_486_400_000, "idle_expires_at" => 1_760_486_400_000,
      "last_active_organization_id" => "org_1", "impersonated_by" => "user_admin"
    }, {
      "object" => "session", "id" => "sess_2", "user_id" => "user_1", "status" => "active",
      "idle_expires_at" => nil, "last_active_organization_id" => nil, "impersonated_by" => nil
    }] })
    sessions = @client.users.list_sessions("user_1")

    req = @http.last
    assert_equal "GET", req.method
    assert_equal "https://api.atlasauth.net/v1/users/user_1/sessions", req.url
    first, second = sessions["data"]
    assert_equal 1_760_486_400_000, first["idle_expires_at"]
    assert_equal first["abandon_at"], first["idle_expires_at"]
    assert_equal "org_1", first["last_active_organization_id"]
    assert_equal "user_admin", first["impersonated_by"]
    assert_nil second["idle_expires_at"]
    assert_nil second["last_active_organization_id"]
    assert_nil second["impersonated_by"]
  end
end
