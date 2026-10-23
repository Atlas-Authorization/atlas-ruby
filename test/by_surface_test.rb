# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"
require "base64"

# Billing add-ons / settings / checks, custom OAuth providers, the Actions
# gallery, session custom data, sign-in settings, SAML SLO + encryption keys,
# dormant accounts, token formats / lifetimes, KMS signing keys, opaque-token
# introspection, device approval and BotID attestations.
class BySurfaceTest < Minitest::Test
  OPS = [
    ["GET", "/v1/billing/subscriptions/bsub_1", nil, ->(c) { c.billing.get_subscription("bsub_1") }],
    ["POST", "/v1/billing/plans/bp_1/sync_entitlements", nil, ->(c) { c.billing.sync_plan_entitlements("bp_1") }],
    ["GET", "/v1/billing/settings", nil, ->(c) { c.billing.get_settings }],
    ["PUT", "/v1/billing/settings", { "default_limit_merge" => "sum" }, ->(c) { c.billing.update_settings({ default_limit_merge: "sum" }) }],
    ["POST", "/v1/billing/check", { "subject_type" => "org", "subject_id" => "org_1", "feature" => "api" },
     ->(c) { c.billing.check_feature({ subject_type: "org", subject_id: "org_1", feature: "api" }) }],
    ["POST", "/v1/billing/usage", { "subject_type" => "user", "subject_id" => "u_1", "quantity" => 1, "idempotency_key" => "k", "feature" => "api", "subscription_id" => "bsub_2" },
     ->(c) { c.billing.report_usage({ subject_type: "user", subject_id: "u_1", quantity: 1, idempotency_key: "k", feature: "api", subscription_id: "bsub_2" }) }],
    ["PATCH", "/v1/billing/plans/bp_1", { "kind" => "addon", "seat_feature_id" => nil }, ->(c) { c.billing.update_plan("bp_1", { kind: "addon", seat_feature_id: nil }) }],
    ["GET", "/v1/custom_oauth_providers", nil, ->(c) { c.custom_oauth_providers.list }],
    ["POST", "/v1/custom_oauth_providers", { "provider_key" => "custom_acme", "display_name" => "Acme", "profile_mapping" => { "fields" => { "email" => "mail" } } },
     ->(c) { c.custom_oauth_providers.create({ provider_key: "custom_acme", display_name: "Acme", profile_mapping: { fields: { email: "mail" } } }) }],
    ["GET", "/v1/custom_oauth_providers/coap_1", nil, ->(c) { c.custom_oauth_providers.get("coap_1") }],
    ["PATCH", "/v1/custom_oauth_providers/coap_1", { "icon_url" => nil }, ->(c) { c.custom_oauth_providers.update("coap_1", { icon_url: nil }) }],
    ["DELETE", "/v1/custom_oauth_providers/coap_1", nil, ->(c) { c.custom_oauth_providers.delete("coap_1") }],
    ["POST", "/v1/custom_oauth_providers/discover", { "issuer" => "https://idp.test" }, ->(c) { c.custom_oauth_providers.discover("https://idp.test") }],
    ["POST", "/v1/custom_oauth_providers/profile_mapping/preview", { "userinfo" => { "mail" => "a" } },
     ->(c) { c.custom_oauth_providers.preview_profile_mapping({ userinfo: { mail: "a" } }) }],
    ["POST", "/v1/custom_oauth_providers/coap_1/profile_mapping/preview", { "id_token" => "a.b.c" },
     ->(c) { c.custom_oauth_providers.preview_profile_mapping({ id_token: "a.b.c" }, id: "coap_1") }],
    ["GET", "/v1/custom_oauth_providers/coap_1/signing_keys", nil, ->(c) { c.custom_oauth_providers.list_signing_keys("coap_1") }],
    ["POST", "/v1/custom_oauth_providers/coap_1/signing_keys", { "alg" => "PS256" }, ->(c) { c.custom_oauth_providers.rotate_signing_key("coap_1", alg: "PS256") }],
    ["POST", "/v1/custom_oauth_providers/coap_1/signing_keys/k1/retire", nil, ->(c) { c.custom_oauth_providers.retire_signing_key("coap_1", "k1") }],
    ["POST", "/v1/sso_connections/sso_1/profile_mapping/preview", { "userinfo" => {} }, ->(c) { c.sso_connections.preview_profile_mapping("sso_1", { userinfo: {} }) }],
    ["GET", "/v1/sso_connections/sso_1/signing_keys", nil, ->(c) { c.sso_connections.list_signing_keys("sso_1") }],
    ["POST", "/v1/sso_connections/sso_1/signing_keys", {}, ->(c) { c.sso_connections.rotate_signing_key("sso_1") }],
    ["POST", "/v1/sso_connections/sso_1/signing_keys/k2/retire", nil, ->(c) { c.sso_connections.retire_signing_key("sso_1", "k2") }],
    ["GET", "/v1/sso_connections/sso_1/saml_encryption_key", nil, ->(c) { c.sso_connections.get_saml_encryption_key("sso_1") }],
    ["POST", "/v1/sso_connections/sso_1/saml_encryption_key", nil, ->(c) { c.sso_connections.create_saml_encryption_key("sso_1") }],
    ["DELETE", "/v1/sso_connections/sso_1/saml_encryption_key/previous", nil, ->(c) { c.sso_connections.retire_previous_saml_encryption_key("sso_1") }],
    ["DELETE", "/v1/sso_connections/sso_1/saml_encryption_key", nil, ->(c) { c.sso_connections.delete_saml_encryption_key("sso_1") }],
    ["PATCH", "/v1/sso_connections/sso_1", { "saml_single_logout" => true, "saml_idp_slo_soap_url" => "https://idp.test/soap" },
     ->(c) { c.sso_connections.update("sso_1", { saml_single_logout: true, saml_idp_slo_soap_url: "https://idp.test/soap" }) }],
    ["GET", "/v1/action_gallery?q=geo", nil, ->(c) { c.action_gallery.list({ q: "geo" }) }],
    ["GET", "/v1/action_gallery/geo-fence", nil, ->(c) { c.action_gallery.get("geo-fence") }],
    ["POST", "/v1/action_gallery/geo-fence/install", { "secrets" => { "K" => "v" } }, ->(c) { c.action_gallery.install("geo-fence", { secrets: { K: "v" } }) }],
    ["GET", "/v1/action_gallery_installs", nil, ->(c) { c.action_gallery.installs }],
    ["POST", "/v1/actions/act_1/gallery_update", {}, ->(c) { c.action_gallery.update("act_1") }],
    ["GET", "/v1/action_templates", nil, ->(c) { c.action_templates.list }],
    ["POST", "/v1/action_templates", { "slug" => "mine" }, ->(c) { c.action_templates.create({ slug: "mine" }) }],
    ["GET", "/v1/action_templates/atpl_1", nil, ->(c) { c.action_templates.get("atpl_1") }],
    ["PATCH", "/v1/action_templates/atpl_1", { "summary" => "s" }, ->(c) { c.action_templates.update("atpl_1", { summary: "s" }) }],
    ["DELETE", "/v1/action_templates/atpl_1", nil, ->(c) { c.action_templates.delete("atpl_1") }],
    ["POST", "/v1/action_templates/atpl_1/versions", { "version" => "1.0.0", "code" => "x" }, ->(c) { c.action_templates.add_version("atpl_1", { version: "1.0.0", code: "x" }) }],
    ["POST", "/v1/action_templates/atpl_1/versions/1.0.0/submit", nil, ->(c) { c.action_templates.submit_version("atpl_1", "1.0.0") }],
    ["DELETE", "/v1/action_templates/atpl_1/versions/1.0.0", nil, ->(c) { c.action_templates.delete_version("atpl_1", "1.0.0") }],
    ["POST", "/v1/action_templates/atpl_1/publish", nil, ->(c) { c.action_templates.publish("atpl_1") }],
    ["POST", "/v1/action_templates/atpl_1/unlist", nil, ->(c) { c.action_templates.unlist("atpl_1") }],
    ["PUT", "/v1/sessions/sess_1/custom_data", { "custom_data" => nil }, ->(c) { c.sessions.set_custom_data("sess_1", nil) }],
    ["PATCH", "/v1/sessions/sess_1/custom_data", { "custom_data" => { "plan" => nil, "seat" => 2 } },
     ->(c) { c.sessions.update_custom_data("sess_1", { plan: nil, seat: 2 }) }],
    ["PUT", "/v1/instance/wallet_rpc_secret", { "chain_id" => 1, "url" => "https://rpc.test" }, ->(c) { c.instance_security.set_wallet_rpc_secret(chain_id: 1, url: "https://rpc.test") }],
    ["PATCH", "/v1/rate_limit_policy", { "rules" => [{ "group" => "fapi.sign_in", "window_seconds" => 60, "max" => 5, "key" => "ip" }] },
     ->(c) { c.rate_limit_policy.update({ rules: [{ group: "fapi.sign_in", window_seconds: 60, max: 5, key: "ip" }] }) }],
    ["PATCH", "/v1/instance", { "auth_config" => { "accountLinkingTrust" => { "google" => "always" } } },
     ->(c) { c.instance.set_account_linking_trust({ "google" => "always" }) }],
    ["PATCH", "/v1/instance", { "auth_config" => { "captcha" => { "provider" => "vercel_botid", "attestationUrl" => "/api/botid" } } },
     ->(c) { c.instance.set_captcha_config({ provider: "vercel_botid", attestationUrl: "/api/botid" }) }],
    ["GET", "/v1/instance/signing_key_provider", nil, ->(c) { c.instance_security.get_signing_key_provider }],
    ["PUT", "/v1/instance/signing_key_provider", { "provider" => "aws_kms", "config" => { "region" => "us-east-1" }, "credentials" => { "access_key_id" => "a" } },
     ->(c) { c.instance_security.set_signing_key_provider({ provider: "aws_kms", config: { region: "us-east-1" }, credentials: { access_key_id: "a" } }) }],
    ["DELETE", "/v1/instance/signing_key_provider", { "emergency" => true }, ->(c) { c.instance_security.remove_signing_key_provider({ emergency: true }) }],
    ["PATCH", "/v1/attack_protection", { "dormant_accounts" => { "enabled" => true, "threshold_days" => 120 } },
     ->(c) { c.attack_protection.update({ dormant_accounts: { enabled: true, threshold_days: 120 } }) }],
    ["PATCH", "/v1/resource_servers/rs_1", { "access_token_format" => "opaque", "introspection_client_ids" => ["oc_api"] },
     ->(c) { c.resource_servers.update("rs_1", { access_token_format: "opaque", introspection_client_ids: ["oc_api"] }) }],
    ["PATCH", "/v1/oauth_clients/oc_1", { "access_token_format" => nil, "token_lifetimes" => { "access_token_ttl_seconds" => 600 } },
     ->(c) { c.oauth_clients.update("oc_1", { access_token_format: nil, token_lifetimes: { access_token_ttl_seconds: 600 } }) }]
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

  def test_constants
    assert_includes Atlas::CAPTCHA_PROVIDERS, "captchafox"
    assert_includes Atlas::CAPTCHA_PROVIDERS, "vercel_botid"
    assert_includes Atlas::BILLING_PROVIDERS, "chargebee"
    assert_equal "session.updated", Atlas::WEBHOOK_EVENT_SESSION_UPDATED
    assert_equal "user.reactivated", Atlas::WEBHOOK_EVENT_USER_REACTIVATED
    assert_equal "account_reactivated", Atlas::EMAIL_TEMPLATE_ACCOUNT_REACTIVATED
  end

  def test_botid_attestation
    secret = "k" * 32
    tok = Atlas::BotId.create_attestation(secret, is_bot: false, ttl_seconds: 3600, now: 1_800_000_000)
    assert tok.start_with?(Atlas::BotId::PREFIX)
    payload, sig = tok.delete_prefix(Atlas::BotId::PREFIX).split(".")
    expect = Base64.urlsafe_encode64(OpenSSL::HMAC.digest("SHA256", secret, Atlas::BotId::PREFIX + payload), padding: false)
    assert_equal expect, sig
    data = JSON.parse(Base64.urlsafe_decode64(payload + ("=" * (-payload.length % 4))))
    assert_equal 1, data["v"]
    assert_equal false, data["is_bot"]
    assert_equal 1_800_000_000, data["iat"]
    assert_equal 300, data["exp"] - data["iat"]
    assert data["jti"].length >= 20
    assert_raises(ArgumentError) { Atlas::BotId.create_attestation("short", is_bot: false) }
  end

  def test_device_authorizations
    seen = []
    status = [200]
    post = lambda do |url, json, headers|
      seen << [url, JSON.parse(json), headers]
      next [403, JSON.generate({ "errors" => [{ "code" => "STEP_UP_REQUIRED", "message" => "Re-authenticate." }] })] if status[0] != 200

      [200, JSON.generate({ "object" => "device_authorization", "id" => "da_1", "user_code" => "WDJB-MJHT",
                            "client" => { "name" => "TV" }, "requires_step_up" => true })]
    end
    d = Atlas::DeviceAuthorizations.new(frontend_api: "https://fapi.test/", session_token: "sess_jwt",
                                        publishable_key: "pk_x", post_impl: post)
    auth = d.lookup(" wdjb mjht ")
    url, body, headers = seen.last
    assert_equal "https://fapi.test/v1/client/me/device_authorizations/lookup", url
    assert_equal({ "user_code" => "WDJB-MJHT" }, body)
    assert_equal "Bearer sess_jwt", headers["Authorization"]
    assert_equal "pk_x", headers["x-publishable-key"]
    assert_equal "TV", auth["client"]["name"]
    d.approve(auth)
    assert_equal "https://fapi.test/v1/client/me/device_authorizations/da_1/approve", seen.last[0]
    d.deny(auth)
    assert_equal "https://fapi.test/v1/client/me/device_authorizations/da_1/deny", seen.last[0]
    status[0] = 403
    err = assert_raises(Atlas::DeviceAuthorizations::Error) { d.approve(auth) }
    assert err.needs_reverification?
    refute err.invalid_code?
    assert_equal "abc", Atlas::DeviceAuthorizations.format_user_code("abc")
    assert_equal "WDJB-MJHT", Atlas::DeviceAuthorizations.user_code_from_url("https://x.test/d?user_code=wdjbmjht")
    assert_nil Atlas::DeviceAuthorizations.user_code_from_url("nope")
  end

  ISSUER = "https://acme.atlas.dev"
  AUD = "https://api.acme.test"

  def introspection_stub(calls, state)
    lambda do |url, form, headers|
      calls << [url, form, headers]
      token = form["token"]
      next [500, ""] if token == "oat_down"
      next [200, JSON.generate({ "active" => false })] if !state[:active] || token == "oat_dead"

      iss = token == "oat_foreign" ? "https://other.test" : ISSUER
      [200, JSON.generate({ "active" => true, "iss" => iss, "sub" => "u_1", "aud" => AUD, "scope" => "read",
                            "client_id" => "oc_1", "exp" => Time.now.to_i + 3600 })]
    end
  end

  def test_access_token_introspection
    calls = []
    state = { active: true }
    v = Atlas::AccessTokenVerifier.new(
      issuer: ISSUER, audience: AUD,
      introspection: { client_id: "oc_api", client_secret: "s3cret", post_impl: introspection_stub(calls, state) }
    )
    ok = v.verify("Bearer oat_live", required_scopes: ["read"])
    assert ok.ok?, ok.description
    assert_equal "u_1", ok.subject
    assert_equal "oc_1", ok.client_id
    _url, form, headers = calls.last
    assert_equal "Basic #{Base64.strict_encode64('oc_api:s3cret')}", headers["Authorization"]
    assert_equal "access_token", form["token_type_hint"]
    v.verify("Bearer oat_live")
    assert_equal 1, calls.length, "cached"
    assert_equal 403, v.verify("Bearer oat_live", required_scopes: ["admin"]).status
    refute v.verify("Bearer oat_dead").ok?
    n = calls.length
    v.verify("Bearer oat_dead")
    assert_equal n, calls.length, "negative answer cached"
    foreign = v.verify("Bearer oat_foreign")
    refute foreign.ok?
    assert_includes foreign.description, "another authorization server"
    down = v.verify("Bearer oat_down")
    refute down.ok?
    assert_includes down.description, "could not be validated"

    plain = Atlas::AccessTokenVerifier.new(issuer: ISSUER, audience: AUD, fetch_impl: ->(_u) { [200, '{"keys":[]}'] })
    refused = plain.verify("Bearer oat_live")
    refute refused.ok?
    assert_includes refused.description, "introspection"

    ec = OpenSSL::PKey::EC.generate("prime256v1")
    jwk = JWT::JWK.new(ec)
    jwks = JSON.generate({ "keys" => [jwk.export.merge(alg: "ES256")] })
    live = Atlas::AccessTokenVerifier.new(
      issuer: ISSUER, audience: AUD, fetch_impl: ->(_u) { [200, jwks] },
      introspection: { client_id: "oc_api", client_secret: "s3cret", introspect_jwts: true,
                       post_impl: introspection_stub(calls, state) }
    )
    token = JWT.encode({ "iss" => ISSUER, "sub" => "u_2", "aud" => AUD, "exp" => Time.now.to_i + 60,
                         "token_use" => "access_token" }, ec, "ES256", { kid: jwk.kid })
    state[:active] = false
    refute live.verify("Bearer #{token}").ok?
    assert_raises(ArgumentError) { Atlas::Introspector.new(issuer: ISSUER, client_id: "", client_secret: "") }
  end

  def test_introspector_cache_bounds_and_expiry
    clock = [1_800_000_000_000]
    hits = [0]
    post = lambda do |_url, _form, _headers|
      hits[0] += 1
      [200, JSON.generate({ "active" => true, "exp" => 1_800_000_005 })]
    end
    i = Atlas::Introspector.new(issuer: ISSUER, client_id: "a", client_secret: "b", cache_max: 2, post_impl: post,
                                now: -> { clock[0] })
    %w[t1 t2 t3].each { |t| refute_nil i.introspect(t) }
    assert_equal 2, i.instance_variable_get(:@cache).size
    i.introspect("t3")
    n = hits[0]
    clock[0] += 6000
    i.introspect("t3")
    assert_equal n + 1, hits[0], "never reused past exp"
  end
end
