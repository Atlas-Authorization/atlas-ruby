# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"

# App roles, org teams/roles, user search + timed bans, API key controls,
# billing providers and subscription management, OAuth server administration,
# ES256 verification, app-claim helpers and the access-token verifier.
class BxSurfaceTest < Minitest::Test
  OPS = [
    ["GET", "/v1/app_roles", nil, ->(c) { c.app_roles.list }],
    ["POST", "/v1/app_roles", { "key" => "support", "name" => "Support" }, ->(c) { c.app_roles.create({ key: "support", name: "Support" }) }],
    ["GET", "/v1/app_roles/support", nil, ->(c) { c.app_roles.get("support") }],
    ["PATCH", "/v1/app_roles/support", { "permissions" => ["a:b"] }, ->(c) { c.app_roles.update("support", { permissions: ["a:b"] }) }],
    ["DELETE", "/v1/app_roles/ar_1", nil, ->(c) { c.app_roles.delete("ar_1") }],
    ["GET", "/v1/app_roles/ar_1/users?limit=5&offset=10", nil, ->(c) { c.app_roles.list_users("ar_1", { limit: 5, offset: 10 }) }],
    ["GET", "/v1/users/u_1/app_roles", nil, ->(c) { c.app_roles.get_for_user("u_1") }],
    ["POST", "/v1/users/u_1/app_roles", { "add" => ["support"] }, ->(c) { c.app_roles.set_for_user("u_1", { add: ["support"] }) }],
    ["DELETE", "/v1/users/u_1/app_roles/support", nil, ->(c) { c.app_roles.remove_from_user("u_1", "support") }],
    ["GET", "/v1/organizations/org_1/teams?user_id=u_1", nil, ->(c) { c.organizations.teams.list("org_1", { user_id: "u_1" }) }],
    ["POST", "/v1/organizations/org_1/teams", { "name" => "Core" }, ->(c) { c.organizations.teams.create("org_1", { name: "Core" }) }],
    ["GET", "/v1/organizations/org_1/teams/tm_1", nil, ->(c) { c.organizations.teams.get("org_1", "tm_1") }],
    ["PATCH", "/v1/organizations/org_1/teams/tm_1", { "name" => "P" }, ->(c) { c.organizations.teams.update("org_1", "tm_1", { name: "P" }) }],
    ["DELETE", "/v1/organizations/org_1/teams/tm_1", nil, ->(c) { c.organizations.teams.delete("org_1", "tm_1") }],
    ["GET", "/v1/organizations/org_1/teams/tm_1/members", nil, ->(c) { c.organizations.teams.list_members("org_1", "tm_1") }],
    ["POST", "/v1/organizations/org_1/teams/tm_1/members", { "user_id" => "u_2" }, ->(c) { c.organizations.teams.add_member("org_1", "tm_1", "u_2") }],
    ["DELETE", "/v1/organizations/org_1/teams/tm_1/members/u_2", nil, ->(c) { c.organizations.teams.remove_member("org_1", "tm_1", "u_2") }],
    ["GET", "/v1/organizations/org_1/roles?own=true", nil, ->(c) { c.organizations.roles.list("org_1", own: true) }],
    ["POST", "/v1/organizations/org_1/roles", { "key" => "editor", "name" => "Editor" }, ->(c) { c.organizations.roles.create("org_1", { key: "editor", name: "Editor" }) }],
    ["PATCH", "/v1/organizations/org_1/roles/r_1", { "name" => "W" }, ->(c) { c.organizations.roles.update("org_1", "r_1", { name: "W" }) }],
    ["DELETE", "/v1/organizations/org_1/roles/r_1?reassign_to=member", nil, ->(c) { c.organizations.roles.delete("org_1", "r_1", reassign_to: "member") }],
    ["GET", "/v1/organizations/by_slug/acme", nil, ->(c) { c.organizations.get_by_slug("acme") }],
    ["GET", "/v1/organizations/check_slug?slug=acme", nil, ->(c) { c.organizations.check_slug("acme") }],
    ["POST", "/v1/organizations/org_1/invitations/inv_1/resend", nil, ->(c) { c.organizations.invitations.resend("org_1", "inv_1") }],
    ["GET", "/v1/users?banned=true&external_id=ext_1&include_total_count=true&query=ada", nil,
     ->(c) { c.users.list({ banned: true, external_id: "ext_1", include_total_count: true, query: "ada" }) }],
    ["POST", "/v1/users/u_1/ban", { "reason" => "spam", "expires_in_seconds" => 3600 }, ->(c) { c.users.ban("u_1", { reason: "spam", expires_in_seconds: 3600 }) }],
    ["POST", "/v1/users/u_1/ban", nil, ->(c) { c.users.ban("u_1") }],
    ["POST", "/v1/api_keys/verify", { "secret" => "ak_x", "required_scopes" => ["read"] }, ->(c) { c.api_keys.verify("ak_x", required_scopes: ["read"]) }],
    ["GET", "/v1/billing/providers", nil, ->(c) { c.billing.list_providers }],
    ["GET", "/v1/billing/providers/polar", nil, ->(c) { c.billing.get_provider("polar") }],
    ["PUT", "/v1/billing/providers/polar", { "environment" => "test", "config" => { "access_token" => "x" } },
     ->(c) { c.billing.set_provider("polar", { environment: "test", config: { access_token: "x" } }) }],
    ["POST", "/v1/billing/providers/polar/test", nil, ->(c) { c.billing.test_provider("polar") }],
    ["DELETE", "/v1/billing/providers/polar?force=true", nil, ->(c) { c.billing.delete_provider("polar", force: true) }],
    ["POST", "/v1/billing/subscriptions/sub_1/change", { "plan_id" => "p_2", "interval" => "year" },
     ->(c) { c.billing.change_subscription("sub_1", { plan_id: "p_2", interval: "year" }) }],
    ["POST", "/v1/billing/subscriptions/sub_1/cancel", { "immediately" => true }, ->(c) { c.billing.cancel_subscription("sub_1", immediately: true) }],
    ["POST", "/v1/billing/subscriptions/sub_1/restore", nil, ->(c) { c.billing.restore_subscription("sub_1") }],
    ["GET", "/v1/instance/signing_keys", nil, ->(c) { c.instance_security.list_signing_keys }],
    ["POST", "/v1/instance/signing_keys/rotate", { "alg" => "ES256" }, ->(c) { c.instance_security.rotate_signing_key({ alg: "ES256" }) }],
    ["GET", "/v1/oauth_initial_access_tokens", nil, ->(c) { c.oauth_initial_access_tokens.list }],
    ["POST", "/v1/oauth_initial_access_tokens", { "max_uses" => 3 }, ->(c) { c.oauth_initial_access_tokens.create({ max_uses: 3 }) }],
    ["DELETE", "/v1/oauth_initial_access_tokens/iat_1", nil, ->(c) { c.oauth_initial_access_tokens.revoke("iat_1") }],
    ["PATCH", "/v1/scim_tokens/st_1", { "scopes" => ["read"] }, ->(c) { c.scim_tokens.update("st_1", { scopes: ["read"] }) }],
    ["GET", "/v1/instance/hooks/before_user_create/calls?status=failed", nil, ->(c) { c.user_hooks.list_before_user_create_calls({ status: "failed" }) }],
    ["GET", "/v1/instance/referrals/calls/rc_1", nil, ->(c) { c.referrals.get_call("rc_1") }]
  ].freeze

  def test_every_new_operation_hits_its_route
    OPS.each do |verb, path, body, call|
      http = Atlas::Test::StubRequester.new
      http.enqueue(body: { "ok" => true })
      call.call(Atlas::Client.new("sk_test_123", http: http))
      req = http.last
      assert_equal verb, req.method, path
      assert_equal "https://api.atlasauth.net#{path}", req.url
      if body.nil?
        assert_nil req.body, "#{verb} #{path} should send no body"
      else
        assert_equal body, JSON.parse(req.body), "#{verb} #{path} body"
      end
    end
  end

  # ── Verification ───────────────────────────────────────────────────────────
  ISSUER = "https://acme.atlas.dev"
  AUD = "https://api.acme.test"

  def setup
    @ec = OpenSSL::PKey::EC.generate("prime256v1")
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @ec_jwk = JWT::JWK.new(@ec)
    @rsa_jwk = JWT::JWK.new(@rsa)
    jwks = JSON.generate({ "keys" => [@ec_jwk.export.merge(alg: "ES256"), @rsa_jwk.export.merge(alg: "RS256")] })
    @fetch = ->(_url) { [200, jwks] }
  end

  def es256(claims, kid: @ec_jwk.kid)
    JWT.encode(claims, @ec, "ES256", { kid: kid })
  end

  def session(extra = {})
    now = Time.now.to_i
    { "iss" => ISSUER, "sub" => "user_1", "iat" => now, "exp" => now + 300 }.merge(extra)
  end

  def test_session_verifier_accepts_es256_and_app_claims
    backend = Atlas::Backend.new(jwks_url: "#{ISSUER}/v1/jwks", issuer: ISSUER, fetch_impl: @fetch)
    result = backend.verify(es256(session("app_roles" => ["support"], "app_permissions" => ["tickets:read"])))
    assert result.ok?, result.reason.inspect
    assert result.has?(app_role: "support")
    refute result.has?(app_role: "admin")
    assert Atlas.has_app_permission?(result.claims, "tickets:read")
    refute Atlas.has_app_permission?(result.claims, "tickets:write")
    assert Atlas.has_app_role?(result.claims, "support")
    assert backend.verify(JWT.encode(session, @rsa, "RS256", { kid: @rsa_jwk.kid })).ok?
    # ES256 over the RSA key's kid, and HS256, never verify.
    refute backend.verify(es256(session, kid: @rsa_jwk.kid)).ok?
    refute backend.verify(JWT.encode(session, "secret" * 8, "HS256", { kid: @ec_jwk.kid })).ok?
    assert_equal %w[RS256 ES256], Atlas::SIGNING_ALGS
  end

  def access(extra = {})
    now = Time.now.to_i
    { "iss" => ISSUER, "sub" => "user_1", "aud" => AUD, "exp" => now + 300, "token_use" => "access_token",
      "scope" => "read write", "client_id" => "oc_1" }.merge(extra)
  end

  def verifier
    Atlas::AccessTokenVerifier.new(issuer: "#{ISSUER}/", audience: AUD, required_scopes: ["read"], fetch_impl: @fetch,
                                   resource_metadata_url: "#{AUD}/.well-known/oauth-protected-resource")
  end

  def test_access_token_verifier
    v = verifier
    ok = v.verify("Bearer #{es256(access)}")
    assert ok.ok?, ok.description
    assert_equal "user_1", ok.subject
    assert_equal "oc_1", ok.client_id
    assert_equal %w[read write], ok.scopes

    none = v.verify(nil)
    assert_equal 401, none.status
    assert_nil none.error
    assert_equal "Bearer scope=\"read\", resource_metadata=\"#{AUD}/.well-known/oauth-protected-resource\"", none.www_authenticate
    assert_equal 400, v.verify("Basic abc").status
    wrong = v.verify("Bearer #{es256(access('aud' => 'https://other.test'))}")
    assert_equal 401, wrong.status
    assert_includes wrong.www_authenticate, 'error="invalid_token"'
    refute v.verify("Bearer #{es256(access('token_use' => 'session'))}").ok?
    refute v.verify("Bearer #{es256(access('cnf' => { 'jkt' => 'x' }))}").ok?
    refute v.verify("Bearer #{es256(access('exp' => Time.now.to_i - 600))}").ok?
    short = v.verify("Bearer #{es256(access('scope' => 'write'))}", required_scopes: ["admin"])
    assert_equal 403, short.status
    assert_equal "insufficient_scope", short.error
    assert_includes short.www_authenticate, 'scope="read admin"'
    assert_raises(ArgumentError) { Atlas::AccessTokenVerifier.new(issuer: ISSUER, audience: []) }
  end

  def test_access_token_guard_and_helpers
    app = ->(env) { [200, {}, [env["atlas.access_token"].subject]] }
    guard = Atlas::AccessTokenGuard.new(app, verifier: verifier)
    status, headers, = guard.call({})
    assert_equal 401, status
    assert headers["www-authenticate"].start_with?("Bearer")
    status, _, body = guard.call({ "HTTP_AUTHORIZATION" => "Bearer #{es256(access)}" })
    assert_equal 200, status
    assert_equal ["user_1"], body

    assert_equal "Bearer", Atlas.build_www_authenticate
    assert_equal "/.well-known/oauth-protected-resource/v1", Atlas.protected_resource_metadata_path("https://api.test/v1/")
    doc = Atlas.protected_resource_metadata(resource: AUD, issuer: "#{ISSUER}/", scopes_supported: ["read"])
    assert_equal [ISSUER], doc["authorization_servers"]
  end
end
