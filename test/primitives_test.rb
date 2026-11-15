# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"
require "base64"

class PrimitivesTest < Minitest::Test
  # ---- recent auth ----
  def test_authenticated_within_and_mfa
    now = Time.at(1_000_000)
    assert Atlas.authenticated_within({ "auth_time" => 999_900 }, 300, now: now)
    refute Atlas.authenticated_within({ "auth_time" => 999_000 }, 300, now: now)
    refute Atlas.authenticated_within({}, 300, now: now)
    assert Atlas.used_multi_factor({ "acr" => "urn:atlas:acr:mfa" })
    assert Atlas.used_multi_factor({ amr: %w[pwd mfa] })
    refute Atlas.used_multi_factor({ "amr" => ["pwd"] })
    assert Atlas.mfa_satisfied({ "sso_connection_id" => "c1" })
    refute Atlas.mfa_satisfied({ "mfa_satisfied" => false, "mfa" => true })
    refute Atlas.mfa_org_satisfied({ "org_mfa_required" => true })
    assert Atlas.mfa_org_satisfied({ "org_mfa_required" => true, "org_mfa_ok" => true, "org_id" => "o1" }, "o1")
    refute Atlas.mfa_org_satisfied({ "org_mfa_required" => true, "org_mfa_ok" => true, "org_id" => "o2" }, "o1")
    assert Atlas::VerifyResult.success({ "amr" => ["mfa"] }).used_multi_factor?
  end

  # ---- transaction token ----
  def test_verify_transaction_token
    key = OpenSSL::PKey::RSA.generate(2048)
    jwks = { "keys" => [JWT::JWK.new(key, kid: "k").export] }
    now = Time.now.to_i
    claims = { "iss" => "https://a.example", "aud" => "example.com", "sub" => "u", "iat" => now, "exp" => now + 60,
               "txn" => "t1", "scope" => "a b", "req_wl" => "w" }
    mint = ->(c, typ = "txntoken+jwt") { JWT.encode(c, key, "RS256", { "kid" => "k", "typ" => typ }) }
    ok = Atlas.verify_transaction_token(mint.call(claims), issuer: "https://a.example/", trust_domain: "example.com", jwks: jwks)
    assert ok.ok?
    assert_equal %w[a b], ok.scopes
    refute Atlas.verify_transaction_token(mint.call(claims, "JWT"), issuer: "https://a.example", trust_domain: "example.com", jwks: jwks).ok?
    refute Atlas.verify_transaction_token(mint.call(claims), issuer: "https://a.example", trust_domain: "other.com", jwks: jwks).ok?
    refute Atlas.verify_transaction_token(mint.call(claims.reject { |k, _| k == "txn" }), issuer: "https://a.example", trust_domain: "example.com", jwks: jwks).ok?
  end

  # ---- webhook dedupe ----
  def test_webhook_dedupe
    store = Atlas::MemoryWebhookStore.new
    body = JSON.generate({ "type" => "user.created" })
    ts = (Time.now.to_f * 1000).to_i
    mac = Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", "whsec_x", "evt_1.#{ts}.#{body}"))
    headers = { "atlas-id" => "evt_1", "atlas-timestamp" => ts.to_s, "atlas-signature" => "v1,#{mac}" }
    first = Atlas::WebhookDedupe.verify(body: body, headers: headers, secret: "whsec_x", store: store)
    refute first.duplicate?
    assert Atlas::WebhookDedupe.verify(body: body, headers: headers, secret: "whsec_x", store: store).duplicate?
    first.release
    refute Atlas::WebhookDedupe.verify(body: body, headers: headers, secret: "whsec_x", store: store).duplicate?
    err = assert_raises(Atlas::WebhookVerificationError) { Atlas::WebhookDedupe.verify(body: body, headers: headers, secret: "wrong", store: store) }
    assert_equal :signature_mismatch, err.reason
  end

  # ---- sid revocation ----
  def test_sid_revocation_list
    stub = Atlas::Test::StubRequester.new
    stub.enqueue(body: { "data" => [{ "sid" => "s1", "revoked_at" => 1000 }], "has_more" => false, "server_time" => 2000 })
    clock = 5000
    list = Atlas::SidRevocationList.new(secret_key: "sk_test_x", http: stub, now: -> { clock }, on_stale: :reject)
    assert list.revoked?("s1")
    refute list.revoked?("s2")
    assert_includes stub.last.url, "/v1/sessions/revoked?since="
    refute list.unavailable?
    clock += 10 * 60_000
    stub.enqueue(status: 500, body: {})
    list.revoked?("s1")
    assert list.unavailable?
  end

  # ---- key mirror ----
  class FakeKeys
    attr_reader :created, :deleted
    def initialize = (@deleted = [])
    def create(body, idempotency_key: nil)
      @created = body
      { "id" => "eak_1", "secret" => "ak_secret_1", "prefix" => "ak_secr", "subject_type" => "user", "subject_id" => "u1",
        "scopes" => body[:scopes], "expires_at" => nil, "revoked_at" => nil, "allowed_ips" => body[:allowed_ips] }
    end
    def delete(id) = @deleted << id
    def list_revoked(_params) = { "data" => [{ "id" => "eak_1", "revoked_at" => 5, "revoked_reason" => "user" }], "has_more" => false, "next_cursor" => "c1" }
  end

  def test_key_mirror
    api = FakeKeys.new
    store = Atlas::MemoryKeyMirrorStore.new
    mirror = Atlas::KeyMirror.new(store: store, api_keys: api, scope_implications: { "admin" => ["*"] }, allowed_scopes: %w[read write admin],
                                  max_staleness_ms: 1000, now: -> { 10_000 })
    mirror.mint({ scopes: ["admin"], allowed_ips: ["10.0.0.0/8"] })
    assert_equal :stale, mirror.verify("ak_secret_1", client_ip: "10.1.2.3").code
    mirror.sync
    assert_equal({ "eak_1" => 5 }, { "eak_1" => store.get("eak_1").revoked_at })
    store.keys["eak_1"].revoked_at = nil
    assert mirror.instance_variable_set(:@memory_sync_at, 10_000) # fresh again
    store.set_last_sync_at(10_000)
    ok = mirror.verify("ak_secret_1", required_scopes: ["write"], client_ip: "10.1.2.3")
    assert ok.valid?
    assert_equal %w[admin read write], ok.effective_scopes
    assert_equal :ip_not_allowed, mirror.verify("ak_secret_1", client_ip: "192.168.0.1").code
    assert_equal :client_ip_required, mirror.verify("ak_secret_1").code
    refute mirror.verify("nope", client_ip: "10.0.0.1").valid?
    mirror.apply_webhook({ "type" => "api_key.revoked", "data" => { "id" => "eak_1" } })
    refute mirror.verify("ak_secret_1", client_ip: "10.1.2.3").valid?
    mirror.apply_webhook({ "type" => "api_key.restored", "data" => { "id" => "eak_1" } })
    assert mirror.verify("ak_secret_1", client_ip: "10.1.2.3").valid?
    mirror.revoke("eak_1")
    assert_equal ["eak_1"], api.deleted
  end

  def test_ip_allowlist_handles_v6_and_garbage
    assert Atlas::KeyMirror.ip_in_allowlist?("2001:db8::1", ["2001:db8::/32"])
    refute Atlas::KeyMirror.ip_in_allowlist?("10.0.0.1", ["2001:db8::/32"])
    refute Atlas::KeyMirror.ip_in_allowlist?("not-an-ip", ["10.0.0.0/8"])
  end

  # ---- resource role mirror ----
  class FakeSource
    def list_types = { "data" => [{ "key" => "doc", "inherit" => true, "roles" => [{ "key" => "editor", "permissions" => ["doc:edit"], "includes" => ["viewer"] }, { "key" => "viewer", "permissions" => ["doc:read"] }] }] }
    def list_resources(_q) = { "data" => [{ "id" => "r1", "type" => "doc", "external_id" => "folder", "parent_id" => nil }, { "id" => "r2", "type" => "doc", "external_id" => "file", "parent_id" => "r1" }], "has_more" => false }
    def list_changes(_q) = { "data" => [{ "change" => "created", "assignment_id" => "a1", "resource_id" => "r1", "subject" => { "type" => "user", "id" => "u1" }, "role" => "editor", "inherit" => true }], "has_more" => false, "next_cursor" => "x" }
  end

  def test_resource_role_mirror_inherits_down_the_tree
    mirror = Atlas::ResourceRoleMirror.new(store: Atlas::MemoryResourceRoleMirrorStore.new, source: FakeSource.new)
    assert_equal({ applied: 1 }, mirror.sync)
    assert mirror.can?({ type: "user", id: "u1" }, "doc:read", { type: "doc", external_id: "file" })
    refute mirror.can?({ type: "user", id: "u2" }, "doc:read", { type: "doc", external_id: "file" })
    assert_equal :unknown_resource, mirror.check({ type: "user", id: "u1" }, "doc:read", { id: "zzz" }).code
    mirror.apply_webhook({ "type" => "resource_role_assignment.deleted", "data" => { "id" => "a1", "resource_id" => "r1", "role" => "editor", "subject" => { "type" => "user", "id" => "u1" } } })
    refute mirror.can?({ type: "user", id: "u1" }, "doc:read", { type: "doc", external_id: "file" })
  end

  # ---- machine client ----
  RFC8032_PRIV = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
  RFC8032_SIG = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

  def test_machine_challenge_is_pure_ed25519_over_the_nonce
    assert_equal Base64.urlsafe_encode64([RFC8032_SIG].pack("H*"), padding: false), Atlas::MachineClient.sign_challenge(RFC8032_PRIV, "")
    assert_includes Atlas::MachineClient.public_key_pem_of(RFC8032_PRIV), "BEGIN PUBLIC KEY"
  end

  def test_machine_client_enrols_mints_and_caches
    public_pem = nil
    mints = 0
    http = lambda do |_m, url, _h, body|
      path = URI.parse(url).path
      b = JSON.parse(body)
      case path
      when "/v1/machines/enroll"
        public_pem = b["public_key_pem"]
        [201, JSON.generate("id" => "mch_1", "status" => "active", "approval_required" => false, "enrolled_at" => 1), {}]
      when "/v1/machines/challenge" then [200, JSON.generate("nonce" => "n#{mints}"), {}]
      when "/v1/machines/token"
        sig = Base64.urlsafe_decode64(b["signature"] + ("=" * ((4 - (b["signature"].length % 4)) % 4)))
        raise "bad signature" unless OpenSSL::PKey.read(public_pem).verify(nil, sig, b["nonce"])

        mints += 1
        [200, JSON.generate("token" => "mt_#{mints}", "expires_in" => 300, "audience" => b["audience"]), {}]
      end
    end
    clock = 1_000_000
    client = Atlas::MachineClient.new(issuer: "https://auth.example.com", store: Atlas::MemoryMachineStore.new, http: http, now: -> { clock })
    refute client.enrolled?
    assert_equal "not_enrolled", assert_raises(Atlas::MachineClientError) { client.get_token }.code
    assert_equal "mch_1", client.enroll(credential: " met_x ", name: "w").machine_id
    assert_equal "mt_1", client.get_token(audience: "api", scopes: %w[b a]).token
    assert_equal "mt_1", client.get_token(audience: "api", scopes: %w[a b]).token
    clock += 250_000
    assert_equal "mt_2", client.get_token(audience: "api", scopes: %w[a b]).token
    client.reset
    refute client.enrolled?
  end

  def test_dpop_proof_and_file_store
    key = Atlas::MachineDpop.generate_key
    client = Atlas::MachineClient.new(issuer: "https://x.example", store: Atlas::MemoryMachineStore.new, dpop_key: key)
    proof = client.dpop_proof(token: "t", method: "get", url: "https://api.example.com/a?b=1")
    header, payload, sig = proof.split(".")
    dec = ->(x) { Base64.urlsafe_decode64(x + ("=" * ((4 - (x.length % 4)) % 4))) }
    h = JSON.parse(dec.call(header))
    p = JSON.parse(dec.call(payload))
    assert_equal "EdDSA", h["alg"]
    assert_equal "https://api.example.com/a", p["htu"]
    assert_equal "GET", p["htm"]
    assert p["ath"]
    assert_equal Atlas::MachineDpop.thumbprint(key), client.dpop_thumbprint
    assert sig && sig.length > 80
    Dir.mktmpdir do |dir|
      store = Atlas::FileMachineStore.new(File.join(dir, "sub", "m.json"))
      assert_nil store.load
      store.save(Atlas::MachineIdentity.new(issuer: "i", machine_id: "m", private_key_pem: "p", public_key_pem: "q", enrolled_at: 1))
      assert_equal "m", store.load.machine_id
      assert_equal "600", format("%o", File.stat(File.join(dir, "sub", "m.json")).mode & 0o777)
      store.clear
      assert_nil store.load
    end
  end

  # ---- web bot auth (RFC 9421 / drafts vectors) ----
  RFC_SEED_PEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n"
  RFC_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
  WBA_NOW = 1_735_689_600

  def test_web_bot_auth_thumbprint_and_signature_base_vector
    jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => RFC_X }
    assert_equal "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", Atlas::WebBotAuth.jwk_thumbprint(jwk)
    built = Atlas::WebBotAuth.build_signature_base(
      method: "POST", url: "https://example.com/foo?param=Value&Pet=dog",
      headers: { "Host" => "example.com", "Date" => "Tue, 20 Apr 2021 02:07:55 GMT", "Content-Type" => "application/json", "Content-Length" => "18" },
      components: %w[date @method @path @authority content-type content-length],
      signature_params: '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
    )
    assert_equal ['"date": Tue, 20 Apr 2021 02:07:55 GMT', '"@method": POST', '"@path": /foo', '"@authority": example.com',
                  '"content-type": application/json', '"content-length": 18',
                  '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'].join("\n"),
                 built[:base]
  end

  def wba_verifier(**opts)
    jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => RFC_X }
    Atlas::WebBotAuth::Verifier.new(fetch_json: ->(_u) { { "keys" => [jwk] } }, now: -> { Time.at(WBA_NOW) }, **opts)
  end

  def wba_sign(**over)
    Atlas::WebBotAuth.sign_request(method: "GET", url: "https://site.example.net/pricing?a=1", signature_agent: "https://bot.example.com",
                                   private_key: RFC_SEED_PEM, created: WBA_NOW, expires: WBA_NOW + 300, **over)
  end

  def test_web_bot_auth_verifies_decides_and_rejects
    headers = wba_sign(nonce: "n1")
    v = wba_verifier(allow: [{ directory: "https://bot.example.com", name: "ExampleBot" }], reject_replays: true)
    d = v.verify(method: "GET", url: "https://site.example.net/pricing?a=1", headers: headers)
    assert d.verified?
    assert_equal "allowed", d.tier
    assert_equal "ExampleBot", d.agent[:name]
    assert_equal "replayed", v.verify(method: "GET", url: "https://site.example.net/pricing?a=1", headers: headers).then { |x| x.reason.to_s == "replayed" ? "replayed" : x.tier }
    # a different path is not what was signed only if @path were covered; @authority is: another host fails
    bad = wba_verifier.verify_result(method: "GET", url: "https://evil.example.net/pricing", headers: headers)
    assert_equal :bad_signature, bad.reason
    assert_equal :no_signature, wba_verifier.verify_result(method: "GET", url: "https://site.example.net/", headers: {}).reason
    tampered = headers.merge("signature" => headers["signature"].sub(/:(.)/) { ":#{$1 == 'A' ? 'B' : 'A'}" })
    assert_equal :bad_signature, wba_verifier.verify_result(method: "GET", url: "https://site.example.net/pricing?a=1", headers: tampered).reason
    blocked = wba_verifier(block: [{ directory: "https://bot.example.com" }]).verify(method: "GET", url: "https://site.example.net/pricing?a=1", headers: wba_sign)
    assert_equal "blocked", blocked.tier
    old = Atlas::WebBotAuth::Verifier.new(fetch_json: ->(_u) { { "keys" => [{ "kty" => "OKP", "crv" => "Ed25519", "x" => RFC_X }] } }, now: -> { Time.at(WBA_NOW + 4000) })
    assert_equal :expired, old.verify_result(method: "GET", url: "https://site.example.net/pricing?a=1", headers: wba_sign).reason
  end

  def test_pinned_fetch_refuses_private_and_non_https
    assert_raises(Atlas::WebBotAuth::PinnedFetch::Refused) { Atlas::WebBotAuth::PinnedFetch.call("http://x.example/d") }
    assert_raises(Atlas::WebBotAuth::PinnedFetch::Refused) { Atlas::WebBotAuth::PinnedFetch.call("https://localhost/d") }
    assert_raises(Atlas::WebBotAuth::PinnedFetch::Refused) { Atlas::WebBotAuth::PinnedFetch.call("https://10.0.0.5/d") }
    assert_raises(Atlas::WebBotAuth::PinnedFetch::Refused) { Atlas::WebBotAuth::PinnedFetch.call("https://x.example/d", resolve: ->(_) { ["127.0.0.1"] }) }
  end

  # ---- device flow ----
  def test_device_flow_polls_through_pending_and_slow_down
    answers = [[200, { "device_code" => "dc", "user_code" => "AB-CD", "verification_uri" => "u", "expires_in" => 600, "interval" => 5 }],
               [400, { "error" => "authorization_pending" }], [400, { "error" => "slow_down" }], [200, { "access_token" => "at" }]]
    calls = []
    http = ->(_m, url, _h, body) { calls << [url, body]; s, j = answers.shift; [s, JSON.generate(j), {}] }
    start = Atlas::DeviceFlow.start(issuer: "https://a.example/", client_id: "cli", scope: %w[openid profile], http: http)
    assert_equal "AB-CD", start.user_code
    assert_equal "https://a.example/oauth2/device_authorization", calls[0][0]
    waits = []
    tokens = Atlas::DeviceFlow.poll(start, http: http, sleeper: ->(s) { waits << s })
    assert_equal "at", tokens["access_token"]
    assert_equal [5, 5, 10], waits
    denied = Atlas::DeviceFlow::Authorization.new(device_code: "d", expires_in: 100, interval: 1, config: start.config)
    http2 = ->(*) { [400, JSON.generate("error" => "access_denied"), {}] }
    assert_equal "access_denied", assert_raises(Atlas::DeviceFlow::Error) { Atlas::DeviceFlow.poll(denied, http: http2, sleeper: ->(_) {}) }.error
  end

  def test_template_settings
    assert_equal({ lifetime_seconds: 300, algorithm: "RS256" }, Atlas::JwtTemplateSettings.build(lifetime_seconds: 300, algorithm: "RS256"))
    assert_equal({ lifetime_seconds: nil }, Atlas::JwtTemplateSettings.build(lifetime_seconds: nil))
    assert_raises(ArgumentError) { Atlas::JwtTemplateSettings.build(lifetime_seconds: 5) }
    assert_raises(ArgumentError) { Atlas::JwtTemplateSettings.build(signing_secret: "short") }
  end
end
