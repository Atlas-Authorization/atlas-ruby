# frozen_string_literal: true

require_relative "test_helper"

# Policy acceptance: the Backend API surface, the policy source helpers (checked
# against vectors computed with the TypeScript reference) and the pol claim.
class PoliciesTest < Minitest::Test
  PSP = Atlas::PolicySourceProtocol
  SECRET = "whsec_policy_source_test_secret"
  NOW = 1_800_000_000_000
  SIG_KEY = "veZ8K1cchaPsRfu/JPTU6fBWAsbUn/e/iaGPyP9nFoU="
  SIG_ALL = "yJ3sPsHcT6fbi40UVNPScqsB9/5UomhRMTD/VcpNlWA="
  SIG_EVENT = "m2QmhSM8RGmN8j3QS0wyVr1kqaHmykmswSug5wyHaVU="

  OPS = [
    ["GET", "/v1/policies?include_retired=true", nil, ->(c) { c.policies.list({ include_retired: true }) }],
    ["POST", "/v1/policies", { "key" => "tos", "title" => "Terms" }, ->(c) { c.policies.create({ key: "tos", title: "Terms" }) }],
    ["GET", "/v1/policies/tos", nil, ->(c) { c.policies.get("tos") }],
    ["PATCH", "/v1/policies/tos", { "status" => "retired", "grace_days" => nil }, ->(c) { c.policies.update("tos", { status: "retired", grace_days: nil }) }],
    ["DELETE", "/v1/policies/tos", nil, ->(c) { c.policies.delete("tos") }],
    ["GET", "/v1/policies/tos/versions", nil, ->(c) { c.policies.versions.list("tos") }],
    ["POST", "/v1/policies/tos/versions", { "version" => "v2", "publish" => true }, ->(c) { c.policies.versions.create("tos", { version: "v2", publish: true }) }],
    ["GET", "/v1/policies/tos/versions/v2", nil, ->(c) { c.policies.versions.get("tos", "v2") }],
    ["PATCH", "/v1/policies/tos/versions/v2", { "summary_of_changes" => nil }, ->(c) { c.policies.versions.update("tos", "v2", { summary_of_changes: nil }) }],
    ["DELETE", "/v1/policies/tos/versions/v2", nil, ->(c) { c.policies.versions.delete("tos", "v2") }],
    ["POST", "/v1/policies/tos/versions/v2/publish", { "effective_at" => NOW }, ->(c) { c.policies.versions.publish("tos", "v2", { effective_at: NOW }) }],
    ["POST", "/v1/policies/tos/versions/v2/publish", {}, ->(c) { c.policies.versions.publish("tos", "v2") }],
    ["POST", "/v1/policies/tos/versions/v2/retire", nil, ->(c) { c.policies.versions.retire("tos", "v2") }],
    ["GET", "/v1/policies/tos/acceptances?version=v2&status=all&limit=5", nil,
     ->(c) { c.policies.list_acceptances("tos", { version: "v2", status: "all", limit: 5 }) }],
    ["GET", "/v1/users/user_1/policies", nil, ->(c) { c.policies.for_user("user_1") }],
    ["GET", "/v1/instance/policy_settings", nil, ->(c) { c.policies.settings.get }],
    ["PATCH", "/v1/instance/policy_settings", { "session_claim" => true }, ->(c) { c.policies.settings.update({ session_claim: true }) }],
    ["GET", "/v1/instance/policy_source", nil, ->(c) { c.policy_source.get }],
    ["PUT", "/v1/instance/policy_source", { "enabled" => true, "endpoint_url" => nil }, ->(c) { c.policy_source.update({ enabled: true, endpoint_url: nil }) }],
    ["DELETE", "/v1/instance/policy_source", nil, ->(c) { c.policy_source.delete }],
    ["POST", "/v1/instance/policy_source/test", nil, ->(c) { c.policy_source.test }],
    ["POST", "/v1/instance/policy_source/sync", nil, ->(c) { c.policy_source.sync }],
    ["GET", "/v1/instance/policy_source/deliveries?kind=fetch&status=failed&limit=2", nil,
     ->(c) { c.policy_source.list_deliveries({ kind: "fetch", status: "failed", limit: 2 }) }],
    ["POST", "/v1/users/user_1/consents",
     { "policy" => "tos", "version" => "v2", "policy_version_id" => "polv_1", "content_sha256" => "ab", "display" => "scroll", "scrolled_to_end" => true, "view_ms" => 1200, "locale" => "en" },
     ->(c) { c.users.record_consent("user_1", { policy: "tos", version: "v2", policy_version_id: "polv_1", content_sha256: "ab", display: "scroll", scrolled_to_end: true, view_ms: 1200, locale: "en" }) }]
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
    assert_equal 24, OPS.length
  end

  def test_export_acceptances_csv_returns_text_and_drops_paging
    http = Atlas::Test::StubRequester.new
    http.enqueue(body: "user_id,policy\nu_1,tos\n")
    out = Atlas::Client.new("sk_test_123", http: http).policies.export_acceptances_csv("tos", { limit: 9, status: "accepted" })
    assert_equal "user_id,policy\nu_1,tos\n", out
    assert_equal "https://api.atlasauth.net/v1/policies/tos/acceptances?status=accepted&format=csv", http.last.url
  end

  def test_event_constants
    assert_equal "user.policy_accepted", Atlas::WEBHOOK_EVENT_USER_POLICY_ACCEPTED
    assert_equal "policy.version_published", Atlas::WEBHOOK_EVENT_POLICY_VERSION_PUBLISHED
  end

  def headers(sig, id = "evt_feed_1", ts = NOW.to_s)
    { "Atlas-Id" => id, "Atlas-Timestamp" => ts, "Atlas-Signature" => sig, "Atlas-Policies-Version" => PSP::VERSION }
  end

  def verify(path, hdrs, now: NOW, method: "GET", secret: SECRET)
    PSP.verify_feed_request(method: method, path_and_query: path, headers: hdrs, secret: secret, now_ms: now)
  end

  def test_verify_feed_request_matches_the_typescript_vectors
    r = verify("/atlas/policies?key=tos", headers("v1,#{SIG_KEY}"), now: NOW + 1000)
    assert r.verified?
    assert_equal "tos", r.key
    assert_equal "evt_feed_1", r.delivery_id
    assert_equal NOW, r.timestamp
    assert_equal "2026-10-24", r.protocol_version
    full = PSP.verify_feed_request(path_and_query: "/atlas/policies", headers: headers("v1,#{SIG_ALL}", "evt_feed_2"), secret: SECRET, now_ms: NOW)
    assert full.verified?
    assert_nil full.key
  end

  def test_verify_accepts_any_of_several_v1_values_and_rack_headers
    assert verify("/atlas/policies?key=tos", headers("v1,AAAA v2,zzzz v1,#{SIG_KEY}"), method: "get").verified?
    rack = headers("v1,#{SIG_KEY}").to_h { |k, v| ["HTTP_#{k.upcase.tr('-', '_')}", v] }
    assert verify("/atlas/policies?key=tos", rack).verified?
  end

  def test_verify_refusals
    key_path = "/atlas/policies?key=tos"
    good = headers("v1,#{SIG_KEY}")
    assert_equal :missing_headers, verify(key_path, {}).reason
    assert_equal :malformed_signature, verify(key_path, headers("v2,abc")).reason
    assert_equal :stale_timestamp, verify(key_path, good, now: NOW + 300_001).reason
    assert_equal :stale_timestamp, verify(key_path, good, now: NOW - 300_001).reason
    assert_equal :stale_timestamp, verify(key_path, headers("v1,#{SIG_KEY}", "evt_feed_1", "nope")).reason
    assert_equal :signature_mismatch, verify("/atlas/policies?key=privacy", good).reason
    assert_equal :signature_mismatch, verify(key_path, good, secret: "other").reason
    assert_equal :signature_mismatch, verify(key_path, headers("v1,!!!!")).reason
    assert_equal :wrong_method, verify(key_path, good, method: "POST").reason
    assert verify(key_path, good, now: NOW + 300_000).verified?, "the tolerance edge is inclusive"
  end

  def test_sign_event_matches_the_typescript_vector
    signed = PSP.sign_event(
      event: { type: "policy.published", key: "tos", version: "2026-10-24", occurred_at: "2026-10-24T00:00:00.000Z" },
      secret: SECRET, id: "evt_out_1", timestamp_ms: NOW + 123
    )
    assert_equal '{"occurred_at":"2026-10-24T00:00:00.000Z","type":"policy.published","key":"tos","version":"2026-10-24"}', signed.body
    assert_equal({ "atlas-id" => "evt_out_1", "atlas-timestamp" => (NOW + 123).to_s, "atlas-signature" => "v1,#{SIG_EVENT}" }, signed.headers)
  end

  def test_sign_event_defaults_and_round_trip
    signed = PSP.sign_event(event: { "type" => "policy.retired", "key" => "tos" }, secret: SECRET)
    body = JSON.parse(signed.body)
    assert_equal "policy.retired", body["type"]
    assert_match(/\A\d{4}-\d\d-\d\dT[\d:.]+Z\z/, body["occurred_at"])
    assert signed.headers["atlas-id"].start_with?("evt_")
    # the same signature scheme Atlas verifies for any signed webhook
    assert Atlas::Webhook.verify(body: signed.body, headers: signed.headers, secret: SECRET).verified?
  end

  def test_pol_claim_helpers
    claims = { "sub" => "u_1", "pol" => { "tos" => "2026-10-24", "privacy" => 3, "bad" => true } }
    assert_equal({ "tos" => "2026-10-24", "privacy" => "3" }, Atlas.policies(claims))
    assert_equal "2026-10-24", Atlas.accepted_policy_version(claims, "tos")
    assert_nil Atlas.accepted_policy_version(claims, "other")
    assert_equal({}, Atlas.policies({ "sub" => "u_1" }))
    assert_equal({}, Atlas.policies({ "pol" => "x" }))
    ok = Atlas::VerifyResult.success(claims)
    assert_equal "2026-10-24", ok.accepted_policy_version(:tos)
    assert_equal({}, Atlas::VerifyResult.failure(:invalid).policies)
  end
end
