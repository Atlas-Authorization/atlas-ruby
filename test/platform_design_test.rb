# frozen_string_literal: true

require_relative "test_helper"

# Sign in with Atlas apps, design (incl. raw image uploads), preflight, cookie
# consent, OAuth provider filters, webhooks, entitlement overrides and org
# policy — request shape and response decoding.
class PlatformDesignTest < Minitest::Test
  PNG = "\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR".b
  JPEG = "\xFF\xD8\xFF\xE0\x00\x10JFIF".b

  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
    @platform = Atlas::Client.new("psk_test_1", http: @http).platform
  end

  def test_atlas_id_app_create_sends_logout_and_branding_fields
    @http.enqueue(body: { "object" => "atlas_id_app", "id" => "aia_1", "client_id" => "cid", "client_secret" => "s" })
    body = {
      name: "Acme", redirect_uris: ["https://acme.com/cb"],
      post_logout_redirect_uris: ["https://acme.com/bye"],
      backchannel_logout_uri: "https://acme.com/bcl", backchannel_logout_session_required: true,
      frontchannel_logout_uri: "https://acme.com/fcl", frontchannel_logout_session_required: false,
      branding: { theme: "dark", accent_color: "#7c3aed", copy: { sign_in_title: "Hi {app}" }, design: { preset: "glass" } }
    }
    app = @platform.atlas_id_apps.create(body, idempotency_key: "k1")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/platform/atlas_id_apps", req.url
    assert_equal "Bearer psk_test_1", req.headers["authorization"]
    assert_equal "k1", req.headers["idempotency-key"]
    sent = JSON.parse(req.body)
    assert_equal "https://acme.com/bcl", sent["backchannel_logout_uri"]
    assert_equal true, sent["backchannel_logout_session_required"]
    assert_equal ["https://acme.com/bye"], sent["post_logout_redirect_uris"]
    assert_equal "Hi {app}", sent["branding"]["copy"]["sign_in_title"]
    assert_equal "s", app["client_secret"]
  end

  def test_atlas_id_app_update_rotate_and_preview
    @http.enqueue(body: { "id" => "aia_1" })
    @platform.atlas_id_apps.update("aia_1", { branding: { accent_color: nil } })
    assert_equal "PATCH", @http.last.method
    assert_equal({ "branding" => { "accent_color" => nil } }, JSON.parse(@http.last.body))

    @http.enqueue(body: { "client_secret" => "new" })
    assert_equal "new", @platform.atlas_id_apps.rotate_secret("aia_1")["client_secret"]
    assert_equal "https://api.atlasauth.net/v1/platform/atlas_id_apps/aia_1/rotate_secret", @http.last.url

    @http.enqueue(body: { "object" => "design_preview", "css" => ":root{}" })
    preview = @platform.atlas_id_apps.preview_design({ preset: "midnight" })
    assert_equal({ "design" => { "preset" => "midnight" } }, JSON.parse(@http.last.body))
    assert_equal ":root{}", preview["css"]
  end

  def test_design_asset_upload_sends_raw_bytes_with_sniffed_content_type
    @http.enqueue(status: 201, body: { "object" => "design_asset", "asset_id" => "dasset_1", "kind" => "background" })
    asset = @client.design.upload_asset(PNG, kind: "background")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/design/assets?kind=background", req.url
    assert_equal "image/png", req.headers["content-type"]
    assert_equal PNG, req.body
    assert_equal Encoding::BINARY, req.body.encoding
    assert_equal "dasset_1", asset["asset_id"]
  end

  def test_upload_honours_an_explicit_content_type_and_platform_path
    @http.enqueue(status: 201, body: { "asset_id" => "dasset_2" })
    @platform.design_assets.upload(JPEG, kind: "logo", content_type: "image/jpeg")
    req = @http.last
    assert_equal "https://api.atlasauth.net/v1/platform/design/assets?kind=logo", req.url
    assert_equal "image/jpeg", req.headers["content-type"]

    @http.enqueue(status: 201, body: { "asset_id" => "dasset_3" })
    @client.design.upload_asset("GIF89a....".b)
    assert_equal "image/gif", @http.last.headers["content-type"]
    assert_equal "https://api.atlasauth.net/v1/design/assets", @http.last.url
  end

  def test_upload_refuses_unknown_bytes_without_a_content_type
    assert_raises(ArgumentError) { @client.design.upload_asset("not an image") }
    assert_empty @http.requests
  end

  def test_design_update_wraps_the_design_and_org_design
    @http.enqueue(body: { "object" => "design", "design" => { "preset" => "glass" }, "warnings" => [] })
    result = @client.design.update({ preset: "glass", palette: { primary: "#112233" } })
    assert_equal "PATCH", @http.last.method
    assert_equal "https://api.atlasauth.net/v1/instance/design", @http.last.url
    assert_equal({ "design" => { "preset" => "glass", "palette" => { "primary" => "#112233" } } }, JSON.parse(@http.last.body))
    assert_equal "glass", result["design"]["preset"]

    @http.enqueue(body: { "object" => "organization_design" })
    @client.organizations.replace_design("org_1", {})
    assert_equal "PUT", @http.last.method
    assert_equal({ "design" => {} }, JSON.parse(@http.last.body))
    assert_includes Atlas::Resources::Design::SECTIONS, "backgroundDark"
  end

  def test_preflight_decodes_typed_findings
    @http.enqueue(body: {
      "object" => "preflight", "ok" => false, "checked_at" => 1,
      "findings" => [{ "severity" => "error", "code" => "OAUTH_PROVIDER_NO_CREDENTIALS",
                       "message" => "Google is on without credentials.", "fix" => "Add them.",
                       "subject" => { "provider" => "google" } }]
    })
    report = @client.instance.preflight
    assert_equal "https://api.atlasauth.net/v1/instance/preflight", @http.last.url
    refute report["ok"]
    finding = report["findings"].first
    assert_equal %w[code fix message severity subject], finding.keys.sort
    assert_equal "google", finding["subject"]["provider"]
  end

  def test_cookie_consent_round_trip
    @http.enqueue(body: { "object" => "cookie_consent", "enabled" => true, "script_url" => "https://cmp.example/s.js" })
    @client.instance.set_cookie_consent({ script_url: "https://cmp.example/s.js", extra_origins: ["https://cdn.cmp.example"] })
    assert_equal "PUT", @http.last.method
    assert_equal "https://api.atlasauth.net/v1/instance/cookie_consent", @http.last.url

    @http.enqueue(body: { "enabled" => false })
    refute @client.instance.delete_cookie_consent["enabled"]
    assert_equal "DELETE", @http.last.method
  end

  def test_oauth_providers_list_filters_and_display_fields
    @http.enqueue(body: { "data" => [{ "provider" => "google", "icon_url" => nil, "mode" => "native" }] })
    page = @client.oauth_providers.list(provider: "google", configured: true)
    assert_equal "https://api.atlasauth.net/v1/oauth_providers?provider=google&configured=true", @http.last.url
    assert_equal "native", page["data"][0]["mode"]

    @http.enqueue(body: { "provider" => "siwe", "setting_values" => { "domain" => "app.example.com" } })
    result = @client.oauth_providers.upsert("siwe", { display_name: "Wallet", mode: "redirect",
                                                      settings: { domain: "app.example.com", rpc_url: nil } })
    sent = JSON.parse(@http.last.body)
    assert_nil sent["settings"]["rpc_url"]
    assert sent["settings"].key?("rpc_url")
    assert_equal "app.example.com", result["setting_values"]["domain"]
  end

  def test_webhook_deliveries_accept_a_limit
    @http.enqueue(body: { "data" => [] })
    @client.webhooks.deliveries("we_1", limit: 10)
    assert_equal "https://api.atlasauth.net/v1/webhook_endpoints/we_1/deliveries?limit=10", @http.last.url
  end

  def test_entitlement_overrides_and_org_entitlements
    @http.enqueue(body: { "id" => "eo_1" })
    @client.entitlement_overrides.create({ subject_type: "org", subject_id: "org_1", plan: "enterprise", limits: { seats: -1 } })
    assert_equal({ "subject_type" => "org", "subject_id" => "org_1", "plan" => "enterprise", "limits" => { "seats" => -1 } },
                 JSON.parse(@http.last.body))

    @http.enqueue(body: { "data" => [] })
    @client.entitlement_overrides.list(subject_type: "org", subject_id: "org_1")
    assert_equal "https://api.atlasauth.net/v1/entitlement_overrides?subject_type=org&subject_id=org_1", @http.last.url

    @http.enqueue(body: { "plan" => "enterprise" })
    @client.organizations.entitlements("org_1")
    assert_equal "https://api.atlasauth.net/v1/organizations/org_1/entitlements", @http.last.url
  end

  def test_org_policy_sends_camel_case_keys_and_nil_clears
    @http.enqueue(body: { "policy" => { "requireMfa" => true } })
    @client.organizations.update_policy("org_1", { requireMfa: true, ipAllowlist: nil, endUserPool: { enabled: true } })
    assert_equal({ "requireMfa" => true, "ipAllowlist" => nil, "endUserPool" => { "enabled" => true } }, JSON.parse(@http.last.body))
    assert_includes Atlas::Resources::Organizations::ORG_POLICY_FIELDS, "maxSessionAgeSeconds"
  end

  def test_messaging_transport_tables
    assert_equal %w[api_key domain region], Atlas::Resources::Messaging.config_keys("email", "mailgun")
    assert_includes Atlas::Resources::Messaging.config_keys("sms", "twilio"), "whatsapp_from"
    assert_nil Atlas::Resources::Messaging.config_keys("sms", "pigeon")
  end

  def test_error_code_constants
    @http.enqueue(status: 422, body: { "errors" => [{ "code" => "UNKNOWN_FIELD", "message" => "x", "param" => "nmae" }] })
    error = assert_raises(Atlas::UnprocessableEntityError) { @client.users.update("user_1", { nmae: "x" }) }
    assert error.has_code?(Atlas::ErrorCode::UNKNOWN_FIELD)
    assert_equal "EMAIL_PROVIDER_REQUIRED", Atlas::ErrorCode::EMAIL_PROVIDER_REQUIRED
  end
end
