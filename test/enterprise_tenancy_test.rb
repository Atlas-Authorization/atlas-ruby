# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"

# The 0.22.0 surface: backend-created tenant organizations, domain verification
# methods, SCIM base URL, trusted-JWT connections, SSO setup return URLs,
# chosen webhook secrets, the platform initial-secret reveal, path-mount
# domains and previous issuers in session verification.
class EnterpriseTenancyTest < Minitest::Test
  OPS = [
    ["POST", "/v1/organizations",
     { "name" => "Acme", "slug" => "acme", "external_id" => "cus_42", "owner_email" => "it@acme.example",
       "role_mappings" => { "org:admin" => "owner" }, "public_metadata" => { "plan" => "pro" } },
     ->(c) { c.organizations.create({ name: "Acme", slug: "acme", external_id: "cus_42", owner_email: "it@acme.example",
                                      role_mappings: { "org:admin" => "owner" }, public_metadata: { plan: "pro" } }) }],
    ["PATCH", "/v1/organizations/org_1", { "external_id" => nil }, ->(c) { c.organizations.update("org_1", { external_id: nil }) }],
    ["GET", "/v1/organizations?external_id=cus_42&metadata%5Bplan%5D=pro", nil,
     ->(c) { c.organizations.list({ external_id: "cus_42", metadata: { plan: "pro" } }) }],
    ["GET", "/v1/organizations", nil, ->(c) { c.organizations.list }],
    ["GET", "/v1/organizations/by_domain/acme.example", nil, ->(c) { c.organizations.find_by_domain("acme.example") }],
    ["GET", "/v1/organizations/by_domain/it%40acme.example?include_unverified=true", nil,
     ->(c) { c.organizations.find_by_domain("it@acme.example", include_unverified: true) }],
    ["GET", "/v1/organizations/org_1/policy", nil, ->(c) { c.organizations.get_policy("org_1") }],
    ["POST", "/v1/organizations/org_1/domains/dom_1/verify", nil, ->(c) { c.organizations.domains.verify("org_1", "dom_1") }],
    ["POST", "/v1/organizations/org_1/domains/dom_1/verify", { "method" => "well_known" },
     ->(c) { c.organizations.domains.verify("org_1", "dom_1", method: "well_known") }],
    ["POST", "/v1/organizations/org_1/domains/dom_1/verify", { "method" => "email", "code" => "123456" },
     ->(c) { c.organizations.domains.verify("org_1", "dom_1", method: "email", code: "123456") }],
    ["POST", "/v1/organizations/org_1/domains/dom_1/verification_email", { "address" => "admin" },
     ->(c) { c.organizations.domains.send_verification_email("org_1", "dom_1", address: "admin") }],
    ["POST", "/v1/organizations/org_1/domains/dom_1/verification_email", {},
     ->(c) { c.organizations.domains.send_verification_email("org_1", "dom_1") }],
    ["GET", "/v1/jwt_connections", nil, ->(c) { c.jwt_connections.list }],
    ["GET", "/v1/jwt_connections/jwc_1", nil, ->(c) { c.jwt_connections.get("jwc_1") }],
    ["POST", "/v1/jwt_connections", { "jwks_uri" => "https://idp.example.com/jwks.json", "issuer" => "https://idp.example.com" },
     ->(c) { c.jwt_connections.create({ jwks_uri: "https://idp.example.com/jwks.json", issuer: "https://idp.example.com" }) }],
    ["PATCH", "/v1/jwt_connections/jwc_1", { "status" => "active" }, ->(c) { c.jwt_connections.update("jwc_1", { status: "active" }) }],
    ["DELETE", "/v1/jwt_connections/jwc_1", nil, ->(c) { c.jwt_connections.delete("jwc_1") }],
    ["GET", "/v1/sso_onboarding_profiles?name=Default", nil, ->(c) { c.sso_onboarding.list(name: "Default") }],
    ["GET", "/v1/sso_onboarding_profiles", nil, ->(c) { c.sso_onboarding.list }],
    ["POST", "/v1/sso_onboarding_profiles/sop_1/tickets", { "organization_id" => "org_1", "return_url" => "https://app.example.com/done" },
     ->(c) { c.sso_onboarding.create_ticket("sop_1", { organization_id: "org_1", return_url: "https://app.example.com/done" }) }],
    ["POST", "/v1/webhook_endpoints", { "url" => "https://hooks.example.com/atlas", "active" => false, "secret" => "whsec_#{'a' * 32}" },
     ->(c) { c.webhooks.endpoints.create({ url: "https://hooks.example.com/atlas", active: false, secret: "whsec_#{'a' * 32}" }) }],
    ["POST", "/v1/webhook_endpoints/we_1/rotate_secret", { "secret" => "whsec_#{'b' * 32}" },
     ->(c) { c.webhooks.endpoints.rotate_secret("we_1", secret: "whsec_#{'b' * 32}") }],
    ["POST", "/v1/webhook_endpoints/we_1/rotate_secret", { "overlap_seconds" => 60, "secret" => "whsec_#{'b' * 32}" },
     ->(c) { c.webhooks.endpoints.rotate_secret("we_1", { overlap_seconds: 60 }, secret: "whsec_#{'b' * 32}") }],
    ["POST", "/v1/webhook_endpoints/we_1/rotate_secret", nil, ->(c) { c.webhooks.endpoints.rotate_secret("we_1") }],
    ["POST", "/v1/platform/apps/app_1/initial_secret/reveal", nil, ->(c) { c.platform.apps.reveal_initial_secret("app_1") }],
    ["POST", "/v1/platform/apps/app_1/initial_secret/reveal?dry_run=true", nil,
     ->(c) { c.platform.apps.reveal_initial_secret("app_1", dry_run: true) }],
    ["POST", "/v1/domains", { "method" => "path", "hostname" => "app.example.com", "base_path" => "/__atlas" },
     ->(c) { c.domains.create({ method: "path", hostname: "app.example.com", base_path: "/__atlas" }) }],
    ["POST", "/v1/users", { "email_address" => ["a@example.com"], "password_hash" => "c2FsdA==$aGFzaA==",
                            "password_hash_algorithm" => "scrypt", "password_hash_params" => { "n" => 16_384, "r" => 8, "p" => 1 } },
     ->(c) { c.users.create({ email_address: ["a@example.com"], password_hash: "c2FsdA==$aGFzaA==",
                              password_hash_algorithm: "scrypt", password_hash_params: { n: 16_384, r: 8, p: 1 } }) }],
    ["PATCH", "/v1/instance/referrals", { "report_linked_atlas_id_signups" => true, "partner_portal_url" => "https://partners.example.com" },
     ->(c) { c.referrals.update({ report_linked_atlas_id_signups: true, partner_portal_url: "https://partners.example.com" }) }],
    ["PUT", "/v1/instance/cookie_consent", { "host_aliases" => ["acme-fapi.atlasauth.net"] },
     ->(c) { c.instance.set_cookie_consent({ host_aliases: ["acme-fapi.atlasauth.net"] }) }],
  ].freeze

  def test_every_operation_hits_its_route
    OPS.each do |verb, path, body, call|
      http = Atlas::Test::StubRequester.new
      client = Atlas::Client.new("sk_test_123", http: http)
      http.enqueue(body: { "ok" => true })
      call.call(client)
      req = http.last
      assert_equal verb, req.method, path
      assert_equal "https://api.atlasauth.net#{path}", req.url
      if body.nil?
        assert_nil req.body, "#{verb} #{path} should send no body"
      else
        assert_equal body, JSON.parse(req.body), "#{verb} #{path}"
      end
    end
  end

  def test_new_webhook_event_names
    assert_equal "sso_connection.activated", Atlas::WEBHOOK_EVENT_SSO_CONNECTION_ACTIVATED
    assert_equal "sso_onboarding_ticket.completed", Atlas::WEBHOOK_EVENT_SSO_ONBOARDING_TICKET_COMPLETED
    assert_equal "scim_group.member_removed", Atlas::WEBHOOK_EVENT_SCIM_GROUP_MEMBER_REMOVED
  end

  ISSUER = "https://app.example.com/__atlas"
  OLD_ISSUER = "https://acme-fapi.atlasauth.net"

  def sign(rsa, jwk, iss)
    now = Time.now.to_i
    JWT.encode({ "iss" => iss, "sub" => "user_1", "iat" => now, "nbf" => now, "exp" => now + 3600 },
               rsa, "RS256", { kid: jwk.kid })
  end

  def test_previous_issuers_are_accepted_and_nothing_else
    rsa = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(rsa)
    fetch = ->(_url) { [200, JSON.generate({ "keys" => [jwk.export] })] }
    plain = Atlas::Backend.new(jwks_url: "#{ISSUER}/v1/jwks", issuer: ISSUER, fetch_impl: fetch)
    moving = Atlas::Backend.new(jwks_url: "#{ISSUER}/v1/jwks", issuer: ISSUER, fetch_impl: fetch,
                                previous_issuers: [OLD_ISSUER])

    assert moving.verify(sign(rsa, jwk, ISSUER)).ok?
    assert moving.verify(sign(rsa, jwk, OLD_ISSUER)).ok?
    refute plain.verify(sign(rsa, jwk, OLD_ISSUER)).ok?
    refute moving.verify(sign(rsa, jwk, "https://other.example.com")).ok?
    assert Atlas::Backend.new(jwks_url: "#{ISSUER}/v1/jwks", issuer: ISSUER, fetch_impl: fetch,
                              previous_issuers: []).verify(sign(rsa, jwk, ISSUER)).ok?
  end
end
