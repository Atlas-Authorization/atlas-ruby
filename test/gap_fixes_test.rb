# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "openssl"

# Gap-fix additions on top of the integrator-platform surface: OIDC org/SSO claims, partner
# link requests (owner and partner sides), key owner/expiry/allowed origins, ORIGIN_NOT_ALLOWED,
# last_failing_since / since=failing_since and the browser atlas_id_tokens route.
class GapFixesTest < Minitest::Test
  OPS = [
    ["GET", "/v1/partner_links/requests?direction=inbound&status=pending%2Cdelivery_failed", nil,
     ->(c) { c.partner_links.requests.list({ direction: "inbound", status: %w[pending delivery_failed] }) }],
    ["GET", "/v1/partner_links/requests/plr_1", nil, ->(c) { c.partner_links.requests.get("plr_1") }],
    ["POST", "/v1/partner_links/requests/plr_1/approve", { "scopes" => ["privacy:execute"] },
     ->(c) { c.partner_links.requests.approve("plr_1", { scopes: ["privacy:execute"] }) }],
    ["POST", "/v1/partner_links/requests/plr_1/approve", {}, ->(c) { c.partner_links.requests.approve("plr_1") }],
    ["POST", "/v1/partner_links/requests/plr_1/deny", nil, ->(c) { c.partner_links.requests.deny("plr_1") }],
    ["PATCH", "/v1/partner_links/pl_1", { "cert_fingerprints" => ["abc"] }, ->(c) { c.partner_links.set_certificates("pl_1", ["abc"]) }],
    ["POST", "/v1/partner_links/outbound/cm/request", { "scopes" => ["privacy:execute"] },
     ->(c) { c.partner_links.outbound.request_link("cm", { scopes: ["privacy:execute"] }) }],
    ["POST", "/v1/secret_keys",
     { "name" => "ci", "owner" => "user:u1", "expires_at" => 1, "allowed_origins" => ["https://app.example.com"] },
     ->(c) { c.secret_keys.create({ name: "ci", owner: "user:u1", expires_at: 1, allowed_origins: ["https://app.example.com"] }) }],
    ["POST", "/v1/webhook_endpoints/we1/replay", { "since" => "failing_since" },
     ->(c) { c.webhooks.endpoints.replay("we1", { since: Atlas::WEBHOOK_REPLAY_SINCE_FAILING }) }],
    ["POST", "/v1/webhook_endpoints/we1/redeliver", { "since" => "failing_since" },
     ->(c) { c.webhooks.endpoints.redeliver("we1", { since: "failing_since" }) }],
    ["POST", "/v1/platform/keys", { "scopes" => ["apps:read"], "allowed_origins" => ["https://a.example.com"] },
     ->(c) { c.platform.keys.create({ scopes: ["apps:read"], allowed_origins: ["https://a.example.com"] }) }]
  ].freeze

  def test_routes
    OPS.each do |verb, path, body, call|
      http = Atlas::Test::StubRequester.new
      client = Atlas::Client.new("psk_test_123", http: http)
      http.enqueue(body: { "ok" => true })
      call.call(client)
      req = http.last
      assert_equal verb, req.method, path
      assert_equal "https://api.atlasauth.net#{path}", req.url
      if body.nil?
        assert_nil req.body
      else
        assert_equal body, JSON.parse(req.body), path
      end
    end
  end

  def test_origin_not_allowed_error
    http = Atlas::Test::StubRequester.new
    client = Atlas::Client.new("sk_test_1", http: http)
    http.enqueue(status: 403, body: { "errors" => [{ "code" => "ORIGIN_NOT_ALLOWED", "message" => "no" }] })
    err = assert_raises(Atlas::PermissionError) { client.users.get("u") }
    assert err.origin_not_allowed?
    assert err.has_code?(Atlas::ErrorCode::ORIGIN_NOT_ALLOWED)
    refute err.insufficient_scope?
  end

  CLAIMS = {
    "sub" => "u1", "org_id" => "org_1", "org_slug" => "acme", "org_role" => "admin",
    "org_permissions" => ["org:read", 3], "orgs" => [{ "id" => "org_1", "slug" => "acme", "role" => "admin" }, { "slug" => "x" }],
    "sso_connection_id" => "sso_1", "sso_organization_id" => "org_1", "sso_connection_type" => "saml", "sso_tenant_id" => "tid", "sso_issuer" => "https://idp", "sso_domain" => "acme.com"
  }.freeze

  def test_oidc_claims
    assert_equal({ id: "org_1", slug: "acme", role: "admin", permissions: ["org:read"] }, Atlas::OIDC.organization_of(CLAIMS))
    assert_equal [{ id: "org_1", slug: "acme", role: "admin" }], Atlas::OIDC.organizations_of(CLAIMS)
    assert_equal({ connection_id: "sso_1", organization_id: "org_1", type: "saml", tenant_id: "tid", issuer: "https://idp", domain: "acme.com" }, Atlas::OIDC.sso_of(CLAIMS))
    assert_nil Atlas::OIDC.organization_of({ "sub" => "u" })
    assert_nil Atlas::OIDC.organizations_of({ "sub" => "u" })
    assert_nil Atlas::OIDC.sso_of({ "sub" => "u" })
    assert_equal "organizations", Atlas::OIDC::SCOPE_ORGANIZATIONS
    assert_equal "organizations", Atlas::OIDC_SCOPE_ORGANIZATIONS
    url = Atlas::OIDC.authorize_url_with_organization("https://atlasauth.net/oauth2/authorize?client_id=c", "acme")
    assert_equal "acme", URI.decode_www_form(URI.parse(url).query).to_h["organization"]
    url = Atlas::OIDC.authorize_url_with_organization(url, "other")
    assert_equal ["other"], URI.decode_www_form(URI.parse(url).query).select { |k, _| k == "organization" }.map(&:last)
  end

  def test_partner_side_request_and_delivery
    http = Atlas::Test::StubRequester.new
    http.enqueue(status: 201, body: { "id" => "plr_1", "request_secret" => "rs_1", "status" => "pending" })
    out = Atlas::PartnerLinkRequests.create(
      { partner: "acme", resource: "ins_1", scopes: ["privacy:execute"], callback_url: "https://acme.test/cb" },
      api_url: "https://api.example.test", http: http
    )
    assert_equal "rs_1", out["request_secret"]
    assert_equal "POST", http.last.method
    assert_equal "https://api.example.test/v1/partner_link_requests", http.last.url
    refute http.last.headers.key?("Authorization")
    assert_equal "https://acme.test/cb", JSON.parse(http.last.body)["callback_url"]

    http.enqueue(body: { "status" => "approved" })
    got = Atlas::PartnerLinkRequests.get("plr_1", request_secret: "rs_1", api_url: "https://api.example.test", http: http)
    assert_equal "approved", got["status"]
    assert_equal "Bearer rs_1", http.last.headers["Authorization"]

    http.enqueue(status: 403, body: { "errors" => [{ "code" => "PARTNER_LINK_UNAVAILABLE", "message" => "no" }] })
    err = assert_raises(Atlas::PermissionError) { Atlas::PartnerLinkRequests.create({ partner: "x" }, http: http) }
    assert err.has_code?("PARTNER_LINK_UNAVAILABLE")

    delivery = JSON.generate({ object: "partner_link.credentials", request_id: "plr_1", client_id: "c", client_secret: "s" })
    ts = 1_757_937_600_000
    mac = Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", "rs_1", "evt_9.#{ts}.#{delivery}"))
    headers = { "Atlas-Id" => "evt_9", "Atlas-Timestamp" => ts.to_s, "Atlas-Signature" => "v1,#{mac}" }
    ok = Atlas::PartnerLinkRequests.verify_delivery(body: delivery, headers: headers, request_secret: "rs_1", now_ms: ts)
    assert ok.verified?
    assert_equal "s", ok.event["client_secret"]
    refute Atlas::PartnerLinkRequests.verify_delivery(body: delivery, headers: headers, request_secret: "other", now_ms: ts).verified?
    url = "https://acme.test/cb"
    mac2 = Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", "rs_1", "evt_9.#{ts}.#{url}.#{delivery}"))
    h2 = headers.merge("Atlas-Signature" => "v2,#{mac2}")
    assert Atlas::PartnerLinkRequests.verify_delivery(body: delivery, headers: h2, request_secret: "rs_1", now_ms: ts, url: url).verified?
  end

  def test_browser_atlas_id_tokens_route
    http = Atlas::Test::StubRequester.new
    http.enqueue(body: { "jwt" => "j", "expires_in" => 60, "integration" => "referalli", "audience" => "a", "issuer" => "i", "jwks_uri" => "u" })
    out = Atlas::AtlasIdTokens.fetch(frontend_api: "https://clerk.example.test/", publishable_key: "pk_test_1",
                                     integration: "referalli", access_token: "at_1", origin: "https://app.example.com", http: http)
    assert_equal "j", out["jwt"]
    assert_equal "POST", http.last.method
    assert_equal "https://clerk.example.test/v1/client/integrations/referalli/atlas_id_tokens?publishable_key=pk_test_1", http.last.url
    assert_equal "Bearer at_1", http.last.headers["Authorization"]
    assert_equal "https://app.example.com", http.last.headers["Origin"]

    http.enqueue(body: { "jwt" => "j" })
    Atlas::AtlasIdTokens.fetch(frontend_api: "https://clerk.example.test", publishable_key: "pk_test_1",
                               integration: "referalli", access_token: "at_1", dpop_proof: "proof", http: http)
    assert_equal "DPoP at_1", http.last.headers["Authorization"]
    assert_equal "proof", http.last.headers["DPoP"]

    http.enqueue(status: 403, body: { "errors" => [] })
    assert_nil Atlas::AtlasIdTokens.fetch(frontend_api: "https://clerk.example.test", publishable_key: "pk", integration: "x", access_token: "at", http: http)
    assert_nil Atlas::AtlasIdTokens.fetch(frontend_api: "https://clerk.example.test", publishable_key: "pk", integration: "x", access_token: "", http: http)
  end
end
