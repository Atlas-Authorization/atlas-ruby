# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "openssl"

# The integrator-platform surface (2026-10-24): secret keys, whoami, partner links,
# privacy executor, integrations, status feed, notices / advisories / audit exports,
# webhook endpoint health and replay, dry run, traceparent, key formats, the v2
# webhook signature and the new error fields.
class IntegratorPlatformTest < Minitest::Test
  OPS = [
    ["GET", "/v1/whoami", nil, ->(c) { c.whoami.get }],
    ["POST", "/v1/secret_keys", { "name" => "ci", "scopes" => ["users:read"] }, ->(c) { c.secret_keys.create({ name: "ci", scopes: ["users:read"] }) }],
    ["POST", "/v1/secret_keys?dry_run=true", { "name" => "ci" }, ->(c) { c.secret_keys.create({ name: "ci" }, dry_run: true) }],
    ["GET", "/v1/secret_keys?metadata%5Bteam%5D=a", nil, ->(c) { c.secret_keys.list({ metadata: { team: "a" } }) }],
    ["GET", "/v1/secret_keys/sk_1", nil, ->(c) { c.secret_keys.get("sk_1") }],
    ["PATCH", "/v1/secret_keys/sk_1", { "name" => "x" }, ->(c) { c.secret_keys.update("sk_1", { name: "x" }) }],
    ["POST", "/v1/secret_keys/sk_1/rotate", { "overlap_seconds" => 0 }, ->(c) { c.secret_keys.rotate("sk_1", { overlap_seconds: 0 }) }],
    ["POST", "/v1/secret_keys/sk_1/revoke", nil, ->(c) { c.secret_keys.revoke("sk_1") }],
    ["GET", "/v1/keys", nil, ->(c) { c.keys.list }],
    ["POST", "/v1/keys/revoke_leaked", { "keys" => ["atlas_live_sk_x"] }, ->(c) { c.keys.revoke_leaked({ keys: ["atlas_live_sk_x"] }) }],
    ["GET", "/v1/operator", nil, ->(c) { c.keys.operator }],
    ["POST", "/v1/oauth/token", nil, ->(c) { c.keys.client_credentials(client_id: "a", client_secret: "b") }],
    ["POST", "/v1/partner_links", { "partner" => "cookiemunch", "scopes" => ["privacy:execute"] }, ->(c) { c.partner_links.create({ partner: "cookiemunch", scopes: ["privacy:execute"] }) }],
    ["GET", "/v1/partner_links", nil, ->(c) { c.partner_links.list }],
    ["GET", "/v1/partner_links/pl_1", nil, ->(c) { c.partner_links.get("pl_1") }],
    ["POST", "/v1/partner_links/pl_1/rotate_secret", nil, ->(c) { c.partner_links.rotate_secret("pl_1") }],
    ["DELETE", "/v1/partner_links/pl_1", nil, ->(c) { c.partner_links.revoke("pl_1") }],
    ["GET", "/v1/partner_links/outbound", nil, ->(c) { c.partner_links.outbound.list }],
    ["PUT", "/v1/partner_links/outbound/cm", { "token" => "t" }, ->(c) { c.partner_links.outbound.save("cm", { token: "t" }) }],
    ["POST", "/v1/partner_links/outbound/cm/test", nil, ->(c) { c.partner_links.outbound.test("cm") }],
    ["DELETE", "/v1/partner_links/outbound/cm", nil, ->(c) { c.partner_links.outbound.remove("cm") }],
    ["GET", "/v1/atlas_id_apps", nil, ->(c) { c.atlas_id_apps.list_apps }],
    ["GET", "/v1/atlas_id_apps/a_1/users?email=a%40b.c", nil, ->(c) { c.atlas_id_apps.lookup("a_1", "a@b.c") }],
    ["DELETE", "/v1/atlas_id_apps/a_1/grants/g_1", nil, ->(c) { c.atlas_id_apps.revoke_grant("a_1", "g_1") }],
    ["GET", "/v1/privacy", nil, ->(c) { c.privacy.discover }],
    ["GET", "/v1/privacy/presets/cookiemunch", nil, ->(c) { c.privacy.preset("cookiemunch") }],
    ["POST", "/v1/privacy/lookup", { "emails" => ["a@b.c"] }, ->(c) { c.privacy.lookup({ emails: ["a@b.c"] }) }],
    ["POST", "/v1/privacy/requests", { "subjectId" => "u", "type" => "restriction", "caseId" => "c" }, ->(c) { c.privacy.create_request({ subjectId: "u", type: "restriction", caseId: "c" }) }],
    ["GET", "/v1/privacy/requests/pr_1", nil, ->(c) { c.privacy.get_request("pr_1") }],
    ["POST", "/v1/privacy/requests/pr_1/cancel", nil, ->(c) { c.privacy.cancel_request("pr_1") }],
    ["GET", "/v1/instance/privacy_orchestrator", nil, ->(c) { c.privacy.orchestrator.get }],
    ["PUT", "/v1/instance/privacy_orchestrator", { "provider" => "cookiemunch" }, ->(c) { c.privacy.orchestrator.set({ provider: "cookiemunch" }) }],
    ["DELETE", "/v1/instance/privacy_orchestrator", nil, ->(c) { c.privacy.orchestrator.delete }],
    ["GET", "/v1/instance/integrations", nil, ->(c) { c.integrations.list }],
    ["GET", "/v1/instance/integrations/ref", nil, ->(c) { c.integrations.get("ref") }],
    ["PUT", "/v1/instance/integrations/ref?dry_run=true", { "enabled" => true }, ->(c) { c.integrations.set("ref", { enabled: true }, dry_run: true) }],
    ["DELETE", "/v1/instance/integrations/ref", nil, ->(c) { c.integrations.delete("ref") }],
    ["GET", "/v1/instance/integrations/ref/deliveries?trace=t1", nil, ->(c) { c.integrations.deliveries("ref", { trace: "t1" }) }],
    ["POST", "/v1/instance/integrations/ref/events_secret", nil, ->(c) { c.integrations.events_secret("ref") }],
    ["POST", "/v1/instance/integrations/ref/atlas_id_tokens", nil, ->(c) { c.integrations.atlas_id_tokens("ref") }],
    ["POST", "/v1/sessions/s_1/integration_tokens/referalli", { "audience_hint" => "x" }, ->(c) { c.integrations.get_token("s_1", for: "referalli", audience_hint: "x") }],
    ["POST", "/v1/sessions/s_1/integration_tokens/referalli", nil, ->(c) { c.sessions.get_token("s_1", for: "referalli") }],
    ["POST", "/v1/integrations/verify_errors", { "code" => "x" }, ->(c) { c.integrations.report_verify_error({ code: "x" }) }],
    ["GET", "/v1/integrations/ref/card", nil, ->(c) { c.integrations.card("ref") }],
    ["POST", "/v1/integrations/ref/card/actions/revoke_sessions", nil, ->(c) { c.integrations.card_revoke_sessions("ref") }],
    ["GET", "/v1/public/instances/ins_1", nil, ->(c) { c.integrations.public_instance("ins_1") }],
    ["GET", "/v1/status", nil, ->(c) { c.status.get }],
    ["GET", "/v1/instance/status_subscription", nil, ->(c) { c.status.subscription.get }],
    ["PUT", "/v1/instance/status_subscription", { "enabled" => true }, ->(c) { c.status.subscription.set({ enabled: true }) }],
    ["DELETE", "/v1/instance/status_subscription", nil, ->(c) { c.status.subscription.delete }],
    ["POST", "/v1/instance/status_subscription/rotate_feed", nil, ->(c) { c.status.subscription.rotate_feed }],
    ["GET", "/v1/instance/status_incidents?open=true&limit=5", nil, ->(c) { c.status.incidents({ open: true, limit: 5 }) }],
    ["GET", "/v1/instance/status_dependencies", nil, ->(c) { c.status.dependencies.list }],
    ["POST", "/v1/instance/status_dependencies", { "url" => "u" }, ->(c) { c.status.dependencies.create({ url: "u" }) }],
    ["GET", "/v1/instance/status_dependencies/d1", nil, ->(c) { c.status.dependencies.get("d1") }],
    ["PATCH", "/v1/instance/status_dependencies/d1", { "name" => "n" }, ->(c) { c.status.dependencies.update("d1", { name: "n" }) }],
    ["DELETE", "/v1/instance/status_dependencies/d1", nil, ->(c) { c.status.dependencies.delete("d1") }],
    ["POST", "/v1/instance/status_dependencies/d1/refresh", nil, ->(c) { c.status.dependencies.refresh("d1") }],
    ["GET", "/v1/instance/notices?all=true", nil, ->(c) { c.notices.list({ all: true }) }],
    ["POST", "/v1/instance/notices/n1/acknowledge", nil, ->(c) { c.notices.acknowledge("n1") }],
    ["GET", "/v1/security_advisories", nil, ->(c) { c.security_advisories.list }],
    ["POST", "/v1/security_advisories/a1/acknowledge", nil, ->(c) { c.security_advisories.acknowledge("a1") }],
    ["GET", "/v1/public/security_advisories", nil, ->(c) { c.security_advisories.list_public }],
    ["GET", "/v1/audit_exports", nil, ->(c) { c.audit_exports.list }],
    ["GET", "/v1/audit_exports/ae1", nil, ->(c) { c.audit_exports.get("ae1") }],
    ["POST", "/v1/audit_exports", { "url" => "u" }, ->(c) { c.audit_exports.create({ url: "u" }) }],
    ["PATCH", "/v1/audit_exports/ae1", { "active" => false }, ->(c) { c.audit_exports.update("ae1", { active: false }) }],
    ["DELETE", "/v1/audit_exports/ae1", nil, ->(c) { c.audit_exports.delete("ae1") }],
    ["POST", "/v1/audit_exports/ae1/test", nil, ->(c) { c.audit_exports.test("ae1") }],
    ["POST", "/v1/audit_exports/ae1/rotate_secret", nil, ->(c) { c.audit_exports.rotate_secret("ae1") }],
    ["GET", "/v1/instance/sub_processors", nil, ->(c) { c.sub_processors.list }],
    ["GET", "/v1/entitlements", nil, ->(c) { c.entitlements.get }],
    ["GET", "/v1/integration-health", nil, ->(c) { c.integration_health.get }],
    ["GET", "/v1/integration-health/providers", nil, ->(c) { c.integration_health.providers }],
    ["GET", "/v1/embed?instance=ins_1", nil, ->(c) { c.embed.get({ instance: "ins_1" }) }],
    ["GET", "/v1/instance/csp", nil, ->(c) { c.embed.csp }],
    ["GET", "/v1/openapi/diff?since=2026-10-15&surface=bapi", nil, ->(c) { c.openapi.diff({ since: "2026-10-15", surface: "bapi" }) }],
    ["GET", "/.well-known/api-catalog", nil, ->(c) { c.openapi.api_catalog }],
    ["GET", "/v1/instance/unknown_fields_report?days=7", nil, ->(c) { c.instance.unknown_fields_report(days: 7) }],
    ["GET", "/v1/instance/preflight?min_severity=warn&include_suppressed=true", nil,
     ->(c) { c.instance.preflight_filtered({ min_severity: "warn", include_suppressed: true }) }],
    ["GET", "/v1/messaging_providers/email", nil, ->(c) { c.messaging.get_channel("email") }],
    ["GET", "/v1/delivery_health?kind=webhook", nil, ->(c) { c.delivery_health.get({ kind: "webhook" }) }],
    ["PUT", "/v1/delivery_health/webhook/we1/alert_contacts", { "alert_contacts" => ["a@b.c"] }, ->(c) { c.delivery_health.set_alert_contacts("webhook", "we1", ["a@b.c"]) }],
    ["GET", "/v1/meta/egress_ips", nil, ->(c) { c.meta.egress_ips }],
    ["GET", "/v1/meta/egress_ips", nil, ->(c) { c.webhooks.egress_ips }],
    ["GET", "/v1/webhook_endpoints/we1", nil, ->(c) { c.webhooks.endpoints.get("we1") }],
    ["GET", "/v1/webhook_endpoints?metadata%5Bk%5D=v&starting_after=we0", nil, ->(c) { c.webhooks.endpoints.list({ metadata: { k: "v" }, starting_after: "we0" }) }],
    ["POST", "/v1/webhook_endpoints?dry_run=true", { "url" => "u" }, ->(c) { c.webhooks.endpoints.create({ url: "u" }, dry_run: true) }],
    ["PUT", "/v1/webhook_endpoints/by_url", { "url" => "u" }, ->(c) { c.webhooks.endpoints.put_by_url({ url: "u" }) }],
    ["POST", "/v1/webhook_endpoints/we1/test?wait=10", nil, ->(c) { c.webhooks.endpoints.test("we1", wait: 10) }],
    ["POST", "/v1/webhook_endpoints/we1/redeliver", { "since" => 1 }, ->(c) { c.webhooks.endpoints.redeliver("we1", { since: 1 }) }],
    ["POST", "/v1/webhook_endpoints/we1/replay", { "since" => 1 }, ->(c) { c.webhooks.endpoints.replay("we1", { since: 1 }) }],
    ["GET", "/v1/webhook_endpoints/we1/deliveries?status=failed&until=9&starting_after=d1", nil,
     ->(c) { c.webhooks.deliveries("we1", { status: "failed", until: 9, starting_after: "d1" }) }],
    ["GET", "/v1/users?updated_after=5&order_by=-updated_at", nil, ->(c) { c.users.list({ updated_after: 5, order_by: "-updated_at" }) }],
    ["GET", "/v1/events?since=5&order=asc", nil, ->(c) { c.events.list({ since: 5, order: "asc" }) }],
    ["POST", "/v1/instance/referrals/referalli/install", { "return_to" => "https://x" }, ->(c) { c.referrals.install("referalli", { return_to: "https://x" }) }],
    ["GET", "/v1/platform/whoami", nil, ->(c) { c.platform.whoami }],
    ["GET", "/v1/platform/keys?kind=platform", nil, ->(c) { c.platform.keys.list({ kind: "platform" }) }],
    ["POST", "/v1/platform/keys", { "scopes" => ["apps:read"] }, ->(c) { c.platform.keys.create({ scopes: ["apps:read"] }) }],
    ["PATCH", "/v1/platform/keys/k1", { "name" => "n" }, ->(c) { c.platform.keys.update("k1", { name: "n" }) }],
    ["POST", "/v1/platform/keys/k1/revoke", nil, ->(c) { c.platform.keys.revoke("k1") }],
    ["GET", "/v1/platform/audit_logs?action=key.revoked", nil, ->(c) { c.platform.audit.list({ action: "key.revoked" }) }],
    ["GET", "/v1/platform/audit_streams", nil, ->(c) { c.platform.audit.streams.list }],
    ["POST", "/v1/platform/audit_streams", { "url" => "u" }, ->(c) { c.platform.audit.streams.create({ url: "u" }) }],
    ["PATCH", "/v1/platform/audit_streams/s1", { "active" => false }, ->(c) { c.platform.audit.streams.update("s1", { active: false }) }],
    ["DELETE", "/v1/platform/audit_streams/s1", nil, ->(c) { c.platform.audit.streams.delete("s1") }],
    ["POST", "/v1/platform/audit_streams/s1/test", nil, ->(c) { c.platform.audit.streams.test("s1") }],
    ["POST", "/v1/platform/apps/app_1/secret_keys", {}, ->(c) { c.platform.apps.create_secret_key("app_1") }],
    ["POST", "/v1/platform/apps/app_1/clone_config?dry_run=true", { "from_app_id" => "app_0" }, ->(c) { c.platform.apps.clone_config("app_1", { from_app_id: "app_0" }, dry_run: true) }],
    ["POST", "/v1/platform/apps?dry_run=true", { "external_ref" => "e1", "metadata" => { "a" => "b" } }, ->(c) { c.platform.apps.create({ external_ref: "e1", metadata: { a: "b" } }, dry_run: true) }],
    ["GET", "/v1/platform/apps?metadata%5Bteam%5D=a", nil, ->(c) { c.platform.apps.list({ metadata: { team: "a" } }) }],
    ["POST", "/v1/platform/apps/bulk_delete", { "metadata" => { "t" => "1" }, "dry_run" => true }, ->(c) { c.platform.apps.bulk_delete(nil, metadata: { t: "1" }, dry_run: true) }]
  ].freeze

  def test_every_operation_hits_its_route
    OPS.each do |verb, path, body, call|
      http = Atlas::Test::StubRequester.new
      client = Atlas::Client.new("psk_test_123", http: http)
      http.enqueue(body: { "ok" => true })
      call.call(client)
      req = http.last
      assert_equal verb, req.method, path
      assert_equal "https://api.atlasauth.net#{path}", req.url
      if path == "/v1/oauth/token"
        assert_equal "application/x-www-form-urlencoded", req.headers["content-type"]
        assert_equal "client_credentials", URI.decode_www_form(req.body).to_h["grant_type"]
      elsif body.nil?
        assert_nil req.body, "#{verb} #{path} should send no body"
      else
        assert_equal body, JSON.parse(req.body), "#{verb} #{path}"
      end
    end
    assert_equal 112, OPS.length
  end

  def test_idempotency_key_and_traceparent_headers
    http = Atlas::Test::StubRequester.new
    tp = Atlas::Trace.generate
    client = Atlas::Client.new("sk_test_1", http: http, traceparent: tp)
    http.enqueue(body: {})
    client.privacy.create_request({ subjectId: "u", type: "deletion", caseId: "c" }, idempotency_key: "k" * 20)
    assert_equal "k" * 20, http.last.headers["idempotency-key"]
    assert_equal tp, http.last.headers["traceparent"]
    other = Atlas::Trace.child(tp)
    http.enqueue(body: {})
    client.with_options(traceparent: other).whoami.get
    assert_equal other, http.last.headers["traceparent"]
    http.enqueue(body: {})
    Atlas::Client.new("sk_test_1", http: http).whoami.get
    refute http.last.headers.key?("traceparent")
  end

  def test_trace_helpers
    p = Atlas::Trace.parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
    assert_equal "0af7651916cd43dd8448eb211c80319c", p.trace_id
    assert p.sampled?
    refute Atlas::Trace.valid?("00-00000000000000000000000000000000-b7ad6b7169203331-01")
    refute Atlas::Trace.valid?("nope")
    child = Atlas::Trace.child("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
    assert_equal "0af7651916cd43dd8448eb211c80319c", Atlas::Trace.parse(child).trace_id
    refute_equal "b7ad6b7169203331", Atlas::Trace.parse(child).parent_id
    assert Atlas::Trace.valid?(Atlas::Trace.child(nil))
    assert_equal "x", Atlas::Trace.from_headers({ "HTTP_TRACEPARENT" => "x" })
  end

  def test_key_formats_accept_both
    assert Atlas::KeyFormat.secret_key?("sk_live_abc")
    assert Atlas::KeyFormat.secret_key?("atlas_live_sk_abc")
    assert Atlas::KeyFormat.platform_key?("psk_live_abc")
    assert Atlas::KeyFormat.platform_key?("atlas_test_psk_abc")
    assert Atlas::KeyFormat.publishable_key?("atlas_live_pk_abc")
    assert Atlas::KeyFormat.publishable_key?("pk_test_abc")
    assert Atlas::KeyFormat.webhook_secret?("whsec_abc")
    assert_equal :unknown, Atlas::KeyFormat.kind("atlas_live_zz_abc")
    assert_nil Atlas::KeyFormat.kind("hello")
    assert_equal "live", Atlas::KeyFormat.environment("atlas_live_sk_abc")
    assert_nil Atlas::KeyFormat.environment("sk_live_abc")
  end

  def test_error_fields
    http = Atlas::Test::StubRequester.new
    client = Atlas::Client.new("sk_test_1", http: http)
    http.enqueue(status: 404, body: { "errors" => [{ "code" => "ROUTE_NOT_FOUND", "message" => "no",
                                                    "did_you_mean" => ["/v1/organizations"], "allowed_methods" => ["GET"],
                                                    "docs_url" => "https://atlasauth.net/errors/route_not_found" }] })
    err = assert_raises(Atlas::NotFoundError) { client.users.get("x") }
    assert err.has_code?(Atlas::ErrorCode::ROUTE_NOT_FOUND)
    assert_equal ["/v1/organizations"], err.did_you_mean
    assert_equal ["GET"], err.allowed_methods
    assert_equal "https://atlasauth.net/errors/route_not_found", err.docs_url

    http.enqueue(status: 403, body: { "errors" => [{ "code" => "INSUFFICIENT_SCOPE", "message" => "no",
                                                    "meta" => { "required_scope" => "users:write", "legacy_code" => "SCOPE_MISSING" } }] })
    err = assert_raises(Atlas::PermissionError) { client.users.delete("x") }
    assert err.insufficient_scope?
    assert_equal "users:write", err.required_scope

    http.enqueue(status: 403, body: { "errors" => [{ "code" => "SCOPE_MISSING", "message" => "no" }] })
    assert assert_raises(Atlas::PermissionError) { client.users.delete("x") }.insufficient_scope?

    http.enqueue(status: 403, body: { "errors" => [{ "code" => "STEP_UP_REQUIRED", "message" => "no" }] })
    e = assert_raises(Atlas::PermissionError) { client.users.delete("x") }
    assert e.step_up_required?
    refute e.insufficient_scope?
    assert_equal [], e.did_you_mean
    assert_nil e.docs_url
    assert_equal "PARTNER_LINK_UNAVAILABLE", Atlas::ErrorCode::PARTNER_LINK_UNAVAILABLE
  end

  # --- webhook v2 ---------------------------------------------------------------

  SECRET = "whsec_test_secret"
  NOW = 1_757_937_600_000
  URL = "https://example.com/hooks/atlas"
  BODY = JSON.generate({ id: "evt_1", type: "webhook.test", data: {} })

  def mac(payload)
    Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", SECRET, payload))
  end

  def headers(sig)
    { "Atlas-Id" => "evt_1", "Atlas-Timestamp" => NOW.to_s, "Atlas-Signature" => sig }
  end

  def test_webhook_v2_signature_covers_the_url
    v1 = "v1,#{mac("evt_1.#{NOW}.#{BODY}")}"
    v2 = "v2,#{mac("evt_1.#{NOW}.#{URL}.#{BODY}")}"
    both = "#{v1} #{v2}"
    assert Atlas::Webhook.verify(body: BODY, headers: headers(both), secret: SECRET, now_ms: NOW, url: URL).verified?
    assert Atlas::Webhook.verify(body: BODY, headers: headers(v2), secret: SECRET, now_ms: NOW, url: URL).verified?
    assert Atlas::Webhook.verify(body: BODY, headers: headers(v2), secret: SECRET, now_ms: NOW, url: URL, require_v2: true).verified?
    # replayed to another URL
    r = Atlas::Webhook.verify(body: BODY, headers: headers(v2), secret: SECRET, now_ms: NOW, url: "https://evil.example/x")
    assert_equal :signature_mismatch, r.reason
    # require_v2 refuses a v1-only delivery
    r = Atlas::Webhook.verify(body: BODY, headers: headers(v1), secret: SECRET, now_ms: NOW, url: URL, require_v2: true)
    refute r.verified?
    # without url a v2-only header is not verifiable (unknown version is ignored)
    assert_equal :malformed_signature, Atlas::Webhook.verify(body: BODY, headers: headers(v2), secret: SECRET, now_ms: NOW).reason
    # v1 still passes when a v3 entry is present
    assert Atlas::Webhook.verify(body: BODY, headers: headers("v3,zzz #{v1}"), secret: SECRET, now_ms: NOW).verified?
  end

  def test_privacy_helpers
    sig = "v1,#{mac("evt_1.#{NOW}.#{BODY}")}"
    assert Atlas::Privacy.verify_orchestrator_call(body: BODY, headers: headers(sig), secret: SECRET, now_ms: NOW).verified?
    assert Atlas::Privacy.valid_idempotency_key?("k" * 16)
    refute Atlas::Privacy.valid_idempotency_key?("short")
    assert Atlas::Privacy.privacy_event?({ "type" => "privacy_request.completed" })
    refute Atlas::Privacy.privacy_event?({ "type" => "user.created" })
    assert_equal "privacy:execute", Atlas::SCOPE_PRIVACY_EXECUTE
  end

  def test_constants
    assert_equal "status.incident.created", Atlas::WEBHOOK_EVENT_STATUS_INCIDENT_CREATED
    assert_equal "secret_key.expiring", Atlas::WEBHOOK_EVENT_SECRET_KEY_EXPIRING
    assert_equal "referalli", Atlas::REFERRAL_PROVIDER_ALIASES["referally"]
    assert_includes Atlas::PREFLIGHT_CODES, "status_dependency_outage"
  end

  # --- back-channel logout rack handler ------------------------------------------

  Claims = Struct.new(:sid, :sub)

  class FakeLogout
    def initialize(result) = @result = result

    def verify(token)
      raise @result if @result.is_a?(Exception)

      Claims.new("sess_1", token)
    end
  end

  def rack_env(method, form)
    { "REQUEST_METHOD" => method, "rack.input" => StringIO.new(URI.encode_www_form(form)) }
  end

  def test_backchannel_logout_rack_app
    seen = []
    app = Atlas::BackchannelLogoutApp.new(logout: FakeLogout.new(nil)) { |c| seen << c }
    status, = app.call(rack_env("POST", logout_token: "tok"))
    assert_equal 200, status
    assert_equal "tok", seen.first.sub
    assert_equal 405, app.call(rack_env("GET", {})).first

    bad = Atlas::BackchannelLogoutApp.new(logout: FakeLogout.new(Atlas::InvalidLogoutTokenError.new(:malformed))) { |_| }
    assert_equal 400, bad.call(rack_env("POST", logout_token: "x")).first
    retry_app = Atlas::BackchannelLogoutApp.new(logout: FakeLogout.new(Atlas::InvalidLogoutTokenError.new(:no_keys))) { |_| }
    status, headers, = retry_app.call(rack_env("POST", logout_token: "x"))
    assert_equal 503, status
    assert_equal "30", headers["Retry-After"]
  end
end
