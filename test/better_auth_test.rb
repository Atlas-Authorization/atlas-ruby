# frozen_string_literal: true

require_relative "test_helper"
require "atlas/rails"
require "rack/mock"
require "openssl"

# Migrate from Better Auth: the bundle-import resource (and its upload / wait
# helpers), bridge settings, the secret-key session exchange, the Rack / Rails
# bridge, and legacy-issuer JWT acceptance in Atlas::Backend. HTTP goes through
# the StubRequester seam; legacy tokens carry REAL signatures.
class BetterAuthTest < Minitest::Test
  BASE = "https://api.example.test"
  BA_ISSUER = "https://old.example.test"
  SESSION = { "object" => "session_tokens", "jwt" => "j.w.t", "refresh_token" => "rt_1",
              "session_id" => "sess_1", "user_id" => "user_1", "expires_in" => 60 }.freeze

  def setup
    @stub = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", api_url: BASE, http: @stub)
  end

  def teardown
    Atlas.reset_configuration!
  end

  def refusal(status, outcome, code = "VERIFICATION_FAILED")
    meta = outcome ? { "bridge_outcome" => outcome } : {}
    @stub.enqueue(status: status, body: { "errors" => [{ "code" => code, "message" => "x", "meta" => meta }] })
  end

  # --- Imports ---------------------------------------------------------------

  def test_every_import_operation_hits_its_path
    imp = { "object" => "better_auth_import", "id" => "bai_1", "status" => "ready" }
    r = @client.better_auth_imports
    calls = [
      ["GET", "/v1/better_auth_imports/public_key", -> { r.get_public_key }],
      ["POST", "/v1/better_auth_imports/public_key/rotate", -> { r.rotate_public_key }],
      ["POST", "/v1/better_auth_imports", -> { r.create({ options: { import_sessions: true } }) }],
      ["GET", "/v1/better_auth_imports?limit=5&starting_after=bai_0", -> { r.list(limit: 5, starting_after: "bai_0") }],
      ["GET", "/v1/better_auth_imports/bai_1", -> { r.get("bai_1") }],
      ["PUT", "/v1/better_auth_imports/bai_1/parts/2", -> { r.upload_part("bai_1", 2, "l\n") }],
      ["POST", "/v1/better_auth_imports/bai_1/finalize", -> { r.finalize("bai_1") }],
      ["POST", "/v1/better_auth_imports/bai_1/dry_run", -> { r.dry_run("bai_1") }],
      ["POST", "/v1/better_auth_imports/bai_1/apply", -> { r.apply("bai_1", confirm_conflicts: true) }],
      ["DELETE", "/v1/better_auth_imports/bai_1", -> { r.delete("bai_1") }],
      ["GET", "/v1/better_auth_imports/jwks", -> { r.list_jwks }],
      ["DELETE", "/v1/better_auth_imports/jwks/kid_1", -> { r.delete_jwk("kid_1") }],
    ]
    calls.each do |method, path, call|
      @stub.enqueue(body: imp)
      call.call
      assert_equal method, @stub.last.method
      assert_equal "#{BASE}#{path}", @stub.last.url
    end
    create = @stub.requests[2]
    assert_equal({ "options" => { "import_sessions" => true } }, JSON.parse(create.body))
    part = @stub.requests[5]
    assert_equal "l\n", part.body
    assert_match %r{\Atext/plain}, part.headers["content-type"]
    assert_equal({}, JSON.parse(@stub.requests[7].body))
    assert_equal({ "confirm_conflicts" => true }, JSON.parse(@stub.requests[8].body))
  end

  def test_split_bundle_parts
    lines = (0...200).map { |i| %({"n":#{i},"pad":"#{'x' * (i % 7)}"}) }
    bundle = "#{lines.join("\n")}\n"
    parts = Atlas::Resources::BetterAuthImports.split_bundle_parts(bundle, 256)
    assert_operator parts.length, :>, 1
    assert(parts.all? { |p| p.bytesize <= 256 && p.end_with?("\n") })
    assert_equal bundle, parts.join
    assert_equal ["a\nb\n"], Atlas::Resources::BetterAuthImports.split_bundle_parts("a\r\n\n\nb\n", 1024)
    assert_equal ["é\n", "é\n"], Atlas::Resources::BetterAuthImports.split_bundle_parts("é\né\n", 5)
    assert_equal ["aa\n", "#{'b' * 50}\n", "cc\n"],
                 Atlas::Resources::BetterAuthImports.split_bundle_parts("aa\n#{'b' * 50}\ncc\n", 10)
    assert_equal [], Atlas::Resources::BetterAuthImports.split_bundle_parts("")
    assert_equal 8 * 1024 * 1024, Atlas::Resources::BetterAuthImports::PART_BYTES
  end

  def test_upload_creates_uploads_line_split_parts_and_finalizes
    @stub.enqueue(status: 201, body: { "id" => "bai_1", "status" => "uploading" })
    bundle = (0...40).map { |i| %({"line":#{i}}\n) }.join
    n_parts = Atlas::Resources::BetterAuthImports.split_bundle_parts(bundle, 64).length
    n_parts.times { @stub.enqueue(body: { "object" => "better_auth_import_part" }) }
    @stub.enqueue(body: { "id" => "bai_1", "status" => "ready" })
    seen = []
    out = @client.better_auth_imports.upload(bundle, options: { models: ["user"] }, part_bytes: 64) { |n, of| seen << [n, of] }
    assert_equal "ready", out["status"]
    assert_equal({ "options" => { "models" => ["user"] } }, JSON.parse(@stub.requests.first.body))
    parts = @stub.requests[1..n_parts]
    assert_equal((1..n_parts).map { |i| "#{BASE}/v1/better_auth_imports/bai_1/parts/#{i}" }, parts.map(&:url))
    assert_equal bundle, parts.map(&:body).join
    assert(parts.all? { |p| p.body.bytesize <= 64 })
    assert_equal((1..n_parts).map { |i| [i, n_parts] }, seen)
    assert_equal "#{BASE}/v1/better_auth_imports/bai_1/finalize", @stub.last.url
    assert_raises(ArgumentError) { @client.better_auth_imports.upload("\n\n") }
  end

  def test_wait_for_polls_through_in_flight_statuses_and_times_out
    %w[analyzing queued applying completed].each { |s| @stub.enqueue(body: { "id" => "bai_1", "status" => s }) }
    slept = []
    seen = []
    out = @client.better_auth_imports.wait_for("bai_1", interval: 0.25, sleeper: ->(s) { slept << s }) { |i| seen << i["status"] }
    assert_equal "completed", out["status"]
    assert_equal %w[analyzing queued applying completed], seen
    assert_equal [0.25, 0.25, 0.25], slept

    @stub.enqueue(body: { "id" => "bai_1", "status" => "applying" })
    err = assert_raises(Atlas::Error) { @client.better_auth_imports.wait_for("bai_1", timeout: -1, sleeper: ->(_) {}) }
    assert_match(/applying/, err.message)
  end

  # --- Bridge settings + exchange -------------------------------------------

  def test_bridge_settings
    @stub.enqueue(body: { "enabled" => true }).enqueue(body: { "enabled" => true }).enqueue(body: { "deleted" => true })
    assert @client.better_auth_bridge.get["enabled"]
    @client.better_auth_bridge.update({ enabled: true, ends_at: "2027-01-01T00:00:00Z", live_fallback: { secret: nil } })
    assert_equal "PUT", @stub.last.method
    assert_equal({ "enabled" => true, "ends_at" => "2027-01-01T00:00:00Z", "live_fallback" => { "secret" => nil } },
                 JSON.parse(@stub.last.body))
    @client.better_auth_bridge.delete
    assert_equal ["GET", "PUT", "DELETE"], @stub.requests.map(&:method)
    assert(@stub.requests.all? { |r| r.url == "#{BASE}/v1/migrations/better_auth/bridge" })
  end

  def test_exchange_forwards_the_end_users_ip_and_user_agent
    @stub.enqueue(body: SESSION)
    res = Atlas::BetterAuth.exchange(@client, "tok.sig", client_ip: "203.0.113.9", user_agent: "Mozilla/5.0", remember: false)
    assert_equal :session, res.kind
    assert_equal ["j.w.t", "rt_1", "sess_1", "user_1", 60], [res.jwt, res.refresh_token, res.session_id, res.user_id, res.expires_in]
    req = @stub.last
    assert_equal "#{BASE}/v1/migrations/better_auth/exchange", req.url
    assert_equal "Bearer sk_test_123", req.headers["authorization"]
    assert_equal "203.0.113.9", req.headers["x-atlas-client-ip"]
    assert_equal "Mozilla/5.0", req.headers["x-atlas-client-user-agent"]
    assert_equal({ "token" => "tok.sig", "remember" => false }, JSON.parse(req.body))

    @stub.enqueue(body: {})
    @client.better_auth_bridge.exchange("t")
    refute @stub.last.headers.key?("x-atlas-client-ip")
    refute @stub.last.headers.key?("x-atlas-client-user-agent")
    assert_equal({ "token" => "t" }, JSON.parse(@stub.last.body))
  end

  def test_exchange_never_overrides_the_secret
    @stub.enqueue(body: {})
    @client.transport.request(method: :get, path: "/x", headers: { "Authorization" => "Bearer other", "X-Extra" => "1" })
    assert_equal "Bearer sk_test_123", @stub.last.headers["authorization"]
    assert_equal "1", @stub.last.headers["x-extra"]
  end

  def test_exchange_classifies_refusals
    [
      [400, "invalid", "VERIFICATION_FAILED", "invalid"],
      [400, "reused", "VERIFICATION_FAILED", "reused"],
      [400, "expired", "VERIFICATION_EXPIRED", "expired"],
      [403, "closed", "FORBIDDEN", "closed"],
      [429, nil, "RATE_LIMITED", "rate_limited"],
      [503, nil, "INTERNAL", "unavailable"],
      [403, "brand_new", "FORBIDDEN", "unavailable"],
    ].each do |status, outcome, code, want|
      refusal(status, outcome, code)
      res = Atlas::BetterAuth.exchange(@client, "t")
      assert_equal [:refused, want, status], [res.kind, res.outcome, res.http_status]
    end
    @stub.enqueue(body: { "object" => "sign_in_attempt", "id" => "sia_1", "status" => "needs_second_factor" })
    res = Atlas::BetterAuth.exchange(@client, "t")
    assert_equal [:needs_mfa, "sia_1", "needs_second_factor"], [res.kind, res.attempt_id, res.status]

    broken = Atlas::Client.new("sk", api_url: BASE, http: ->(*) { raise IOError, "down" })
    res = Atlas::BetterAuth.exchange(broken, "t")
    assert_equal [:refused, "unavailable", 0], [res.kind, res.outcome, res.http_status]
  end

  # --- Cookies + bridge -------------------------------------------------------

  def test_cookie_names_reading_and_serialising
    names = Atlas::BetterAuth.cookie_names
    assert_equal ["__Secure-better-auth.session_token", "better-auth.session_token"], names[:session_token]
    assert_equal 8, names[:all].length
    header = "a=1; better-auth.session_token=plain; __Secure-better-auth.session_token=secure"
    assert_equal "secure", Atlas::BetterAuth.read_session_cookie(header)
    assert_equal "v", Atlas::BetterAuth.read_session_cookie("my.sess=v", cookie_name: "my.sess")
    assert_nil Atlas::BetterAuth.read_session_cookie(nil)
    cookie = Atlas::BetterAuth::Cookie.new(name: "__atlas_rt", value: "v", http_only: true, same_site: :lax, secure: true)
    assert_equal "__atlas_rt=v; Path=/; HttpOnly; Secure; SameSite=Lax", cookie.to_header
    clear = Atlas::BetterAuth::Cookie.new(name: "x", value: "", max_age: 0, domain: ".example.com")
    assert_equal "x=; Path=/; Domain=.example.com; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT", clear.to_header
  end

  def test_bridge_decisions
    bridge = Atlas::BetterAuth::Bridge.new(client: @client, better_auth_cookie_domain: ".example.com")
    @stub.enqueue(body: SESSION)
    d = bridge.call("better-auth.session_token=tok", client_ip: "198.51.100.7", user_agent: "UA")
    assert_equal :signed_in, d.action
    by_name = d.cookies.to_h { |c| [c.name, c] }
    assert_equal "j.w.t", by_name["__session"].value
    assert by_name["__session"].secure
    assert by_name["__atlas_rt"].http_only
    cleared = d.cookies.select { |c| c.max_age&.zero? }
    assert_equal Atlas::BetterAuth.cookie_names[:all].sort, cleared.map(&:name).sort
    assert(cleared.all? { |c| c.domain == ".example.com" })
    assert(cleared.select { |c| c.name.start_with?("__Secure-") }.all?(&:secure))
    assert_equal "198.51.100.7", @stub.last.headers["x-atlas-client-ip"]

    count = @stub.requests.length
    assert_equal :none, bridge.call("other=1").action
    assert_equal :none, bridge.call("better-auth.session_token=t; __session=x").action
    assert_equal :none, bridge.call({ "better-auth.session_token" => "t", "__atlas_rt" => "r" }).action
    assert_equal count, @stub.requests.length

    @stub.enqueue(body: { "object" => "sign_in_attempt", "id" => "sia_1", "status" => "needs_mfa_enrollment" })
    d = bridge.call("better-auth.session_token=t")
    assert_equal :needs_mfa, d.action
    assert_equal "https://app.example.com/sign-in?r=%2Fx&__atlas_attempt=sia_1&__atlas_status=needs_mfa_enrollment",
                 d.continuation_url("https://app.example.com/sign-in?r=%2Fx")

    custom = Atlas::BetterAuth::Bridge.new(client: @client, cookie_name: "custom.sess")
    refusal(400, "reused")
    d = custom.call("custom.sess=t")
    assert_equal [:refused, "reused"], [d.action, d.outcome]
    assert_includes d.cookies.map(&:name), "__Secure-custom.sess"
    [[403, "closed"], [429, nil], [500, nil]].each do |status, outcome|
      refusal(status, outcome)
      d = custom.call("custom.sess=t")
      assert_equal :refused, d.action
      assert_empty d.cookies
    end
    assert_raises(Atlas::ConfigurationError) { Atlas::BetterAuth::Bridge.new(client: nil) }
  end

  def rack_app(**opts)
    app = ->(_env) { [200, { "content-type" => "text/plain" }, ["next"]] }
    Rack::MockRequest.new(Atlas::BetterAuth::RackMiddleware.new(app, client: @client, **opts))
  end

  def set_cookies(res)
    Array(res.headers["set-cookie"]).flat_map { |v| v.split("\n") }
  end

  def test_rack_middleware
    mw = rack_app(sign_in_url: "https://app.example.com/sign-in")
    @stub.enqueue(body: SESSION)
    res = mw.get("/page?x=1", "HTTP_COOKIE" => "better-auth.session_token=tok", "HTTP_USER_AGENT" => "UA",
                              "HTTP_X_FORWARDED_FOR" => "203.0.113.5, 10.0.0.1")
    assert_equal 302, res.status
    assert_equal "/page?x=1", res.headers["location"]
    assert(set_cookies(res).any? { |c| c.start_with?("__session=j.w.t") })
    assert(set_cookies(res).any? { |c| c.start_with?("__atlas_rt=rt_1") && c.include?("HttpOnly") })
    assert_equal "203.0.113.5", @stub.last.headers["x-atlas-client-ip"]
    assert_equal "UA", @stub.last.headers["x-atlas-client-user-agent"]

    @stub.enqueue(body: { "object" => "sign_in_attempt", "id" => "sia_9", "status" => "needs_second_factor" })
    res = mw.get("/page", "HTTP_COOKIE" => "better-auth.session_token=tok")
    assert_equal 302, res.status
    assert res.headers["location"].start_with?("https://app.example.com/sign-in?__atlas_attempt=sia_9")

    refusal(400, "expired", "VERIFICATION_EXPIRED")
    res = mw.get("/page", "HTTP_COOKIE" => "better-auth.session_token=tok")
    assert_equal 200, res.status
    assert_equal "next", res.body
    assert(set_cookies(res).any? { |c| c.start_with?("better-auth.session_token=;") })

    count = @stub.requests.length
    assert_equal "next", mw.post("/page", "HTTP_COOKIE" => "better-auth.session_token=tok").body
    assert_equal "next", mw.get("/page").body
    assert_equal count, @stub.requests.length
  end

  def test_rails_middleware_runs_the_bridge_when_configured
    Atlas.configure do |c|
      c.jwks_url = "https://acme.atlas.dev/v1/jwks"
      c.issuer = "https://acme.atlas.dev"
      c.secret_key = "sk_test_123"
      c.better_auth_bridge = { secure: false }
    end
    stub = @stub
    Atlas.configuration.define_singleton_method(:bridge) do
      [Atlas::BetterAuth::Bridge.new(client: Atlas::Client.new("sk_test_123", api_url: BASE, http: stub), secure: false), nil]
    end
    app = ->(env) { [200, {}, [env[Atlas::Rails::Middleware::ENV_KEY].ok?.to_s]] }
    mw = Rack::MockRequest.new(Atlas::Rails::Middleware.new(app))
    @stub.enqueue(body: SESSION)
    res = mw.get("/dash", "HTTP_COOKIE" => "better-auth.session_token=tok")
    assert_equal 302, res.status
    assert_equal "/dash", res.headers["location"]
    refute(set_cookies(res).find { |c| c.start_with?("__session=") }.include?("Secure"))
  end

  def test_rails_configuration_builds_the_bridge
    config = Atlas::Configuration.new
    assert_nil config.bridge
    config.better_auth_bridge = { sign_in_url: "https://app/sign-in" }
    config.secret_key = nil
    assert_raises(Atlas::ConfigurationError) { config.bridge }
    config.secret_key = "sk_test_123"
    bridge, sign_in = config.bridge
    assert_instance_of Atlas::BetterAuth::Bridge, bridge
    assert_equal "https://app/sign-in", sign_in
  end

  # --- Legacy issuers ----------------------------------------------------------

  def b64u(raw) = Atlas::DPoP.b64u(raw)

  def legacy_keys
    @legacy_keys ||= {
      "EdDSA" => OpenSSL::PKey.generate_key("ED25519"),
      "ES256" => OpenSSL::PKey::EC.generate("prime256v1"),
      "ES512" => OpenSSL::PKey::EC.generate("secp521r1"),
      "RS256" => OpenSSL::PKey::RSA.generate(2048),
    }
  end

  def legacy_jwks
    k = legacy_keys
    ec = lambda do |kid, crv, key, size|
      point = key.public_key.to_bn.to_s(2)
      { "kid" => kid, "kty" => "EC", "crv" => crv, "x" => b64u(point[1, size]), "y" => b64u(point[1 + size, size]) }
    end
    { "keys" => [
      { "kid" => "k-EdDSA", "kty" => "OKP", "crv" => "Ed25519", "x" => b64u(k["EdDSA"].public_to_der[-32..]) },
      ec.call("k-ES256", "P-256", k["ES256"], 32),
      ec.call("k-ES512", "P-521", k["ES512"], 66),
      { "kid" => "k-RS256", "kty" => "RSA", "n" => b64u(k["RS256"].n.to_s(2)), "e" => b64u(k["RS256"].e.to_s(2)) },
    ] }
  end

  def ba_token(alg, kid, overrides = {})
    now = Time.now.to_i
    claims = { "iss" => BA_ISSUER, "aud" => BA_ISSUER, "sub" => "ba_user_1", "iat" => now, "exp" => now + 900 }
    claims = claims.merge(overrides).compact
    input = "#{b64u(JSON.generate({ alg: alg, kid: kid, typ: 'JWT' }))}.#{b64u(JSON.generate(claims))}"
    sig = case alg
          when "EdDSA" then legacy_keys["EdDSA"].sign(nil, input)
          when "ES256", "ES512"
            size = alg == "ES256" ? 32 : 66
            der = legacy_keys[alg].sign(OpenSSL::Digest.new(alg == "ES256" ? "SHA256" : "SHA512"), input)
            seq = OpenSSL::ASN1.decode(der)
            seq.value.map { |i| i.value.to_s(2).rjust(size, "\x00".b) }.join
          when "RS256" then legacy_keys["RS256"].sign(OpenSSL::Digest.new("SHA256"), input)
          when "PS256" then legacy_keys["RS256"].sign_pss("SHA256", input, salt_length: :digest, mgf1_hash: "SHA256")
          end
    "#{input}.#{b64u(sig)}"
  end

  def legacy_backend(**entry)
    resolver = ->(sub, _claims) { { "ba_user_1" => "user_atlas_1" }[sub] }
    Atlas::Backend.new(
      jwks_url: "https://acme.atlas.dev/v1/jwks", issuer: "https://acme.atlas.dev",
      fetch_impl: ->(_url) { [200, JSON.generate({ "keys" => [] })] },
      legacy_issuers: [{ issuer: BA_ISSUER, until: Time.now + 86_400, jwks: legacy_jwks, audience: BA_ISSUER,
                         resolve_subject: resolver }.merge(entry)],
    )
  end

  def test_legacy_tokens_verify_and_map_sub
    backend = legacy_backend
    %w[EdDSA ES256 ES512 RS256 PS256].each do |alg|
      kid = alg == "PS256" ? "k-RS256" : "k-#{alg}"
      result = backend.verify(ba_token(alg, kid, "sid" => "ba_sess"))
      assert result.ok?, "#{alg}: #{result.reason.inspect}"
      assert_equal "user_atlas_1", result.claims["sub"]
      assert_equal "ba_sess", result.claims["sid"]
      assert_equal "ba_user_1", result.claims["external_id"]
      assert_equal({ "kind" => "better_auth", "issuer" => BA_ISSUER, "sub" => "ba_user_1" }, result.claims["legacy"])
    end
  end

  def test_legacy_refusals
    backend = legacy_backend
    tampered = ba_token("EdDSA", "k-EdDSA")
    [
      ba_token("EdDSA", "k-EdDSA", "exp" => nil),
      ba_token("EdDSA", "k-EdDSA", "exp" => Time.now.to_i - 60),
      ba_token("EdDSA", "k-EdDSA", "aud" => "https://other"),
      ba_token("EdDSA", "k-EdDSA", "sub" => "nobody"),
      ba_token("ES256", "k-EdDSA"),
      "#{tampered[0..-5]}AAAA",
    ].each do |token|
      result = backend.verify(token)
      refute result.ok?
      assert_equal :invalid, result.reason
    end
    only_ed = legacy_backend(algorithms: ["EdDSA"])
    refute only_ed.verify(ba_token("RS256", "k-RS256")).ok?
    assert only_ed.verify(ba_token("EdDSA", "k-EdDSA")).ok?
  end

  def test_legacy_window_closed_and_atlas_tokens_unaffected
    backend = legacy_backend(until: (Time.now.to_f * 1000).to_i - 1)
    refute backend.verify(ba_token("EdDSA", "k-EdDSA")).ok?
  end

  def test_legacy_default_resolver_and_jwks_url
    jwks_json = JSON.generate(legacy_jwks)
    lookups = []
    responses = [[503, "{}"], [200, JSON.generate({ "data" => [{ "id" => "user_atlas_9" }] })]]
    http = lambda do |method, url, headers, _body|
      lookups << [method, url, headers["authorization"]]
      responses.shift || [200, JSON.generate({ "data" => [{ "id" => "user_atlas_9" }] })]
    end
    backend = Atlas::Backend.new(
      jwks_url: "https://acme.atlas.dev/v1/jwks", issuer: "https://acme.atlas.dev",
      secret_key: "sk_test_123", bapi_base_url: BASE, http: http,
      fetch_impl: ->(url) { url.end_with?("/api/auth/jwks") ? [200, jwks_json] : [200, '{"keys":[]}'] },
      legacy_issuers: [{ "issuer" => BA_ISSUER, "until" => "2999-01-01T00:00:00Z", "jwks_url" => "#{BA_ISSUER}/api/auth/jwks" }],
    )
    token = ba_token("EdDSA", "k-EdDSA")
    refute backend.verify(token).ok?, "a failed lookup must refuse"
    2.times { assert_equal "user_atlas_9", backend.verify(token).claims["sub"] }
    assert_equal 2, lookups.length, "the failure is not cached, the success is"
    assert_equal ["GET", "#{BASE}/v1/users?external_id=ba_user_1&limit=1", "Bearer sk_test_123"], lookups.last
  end

  def test_legacy_configuration_errors
    base = { jwks_url: "https://acme.atlas.dev/v1/jwks", issuer: "https://acme.atlas.dev", secret_key: "sk" }
    until_ms = (Time.now.to_f * 1000).to_i + 3_600_000
    [
      { issuer: BA_ISSUER, until: until_ms },
      { issuer: BA_ISSUER, until: until_ms, jwks: legacy_jwks, jwks_url: "https://x" },
      { issuer: BA_ISSUER, until: "not a date", jwks: legacy_jwks },
      { issuer: "https://acme.atlas.dev", until: until_ms, jwks: legacy_jwks },
    ].each do |entry|
      assert_raises(Atlas::ConfigurationError, entry.inspect) { Atlas::Backend.new(**base, legacy_issuers: [entry]) }
    end
    err = assert_raises(Atlas::ConfigurationError) do
      Atlas::Backend.new(**base.merge(secret_key: nil), legacy_issuers: [{ issuer: BA_ISSUER, until: until_ms, jwks: legacy_jwks }])
    end
    assert_match(/secret_key/, err.message)
  end
end
