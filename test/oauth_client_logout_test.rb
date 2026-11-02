# frozen_string_literal: true

require_relative "test_helper"

# The 0.23.0 surface: oauth_clients.logout, refresh_touches_session /
# add_redirect_origins on client writes and site_key on the captcha secret.
class OAuthClientLogoutTest < Minitest::Test
  OPS = [
    ["POST", "/v1/oauth_clients/oc_1/logout", { "sid" => "sess_1" }, ->(c) { c.oauth_clients.logout("oc_1", "sess_1") }],
    ["POST", "/v1/oauth_clients",
     { "name" => "App", "redirect_uris" => ["https://app.example.com/cb"], "first_party" => true,
       "refresh_touches_session" => true, "add_redirect_origins" => true },
     ->(c) { c.oauth_clients.create({ name: "App", redirect_uris: ["https://app.example.com/cb"], first_party: true,
                                      refresh_touches_session: true, add_redirect_origins: true }) }],
    ["PATCH", "/v1/oauth_clients/oc_1", { "refresh_touches_session" => false, "add_redirect_origins" => true },
     ->(c) { c.oauth_clients.update("oc_1", { refresh_touches_session: false, add_redirect_origins: true }) }],
    ["PUT", "/v1/instance/captcha_secret", { "secret" => "0x4AAA", "provider" => "turnstile", "site_key" => "0x4BBB" },
     ->(c) { c.instance_security.set_captcha_secret({ secret: "0x4AAA", provider: "turnstile", site_key: "0x4BBB" }) }]
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
      assert_equal body, JSON.parse(req.body), "#{verb} #{path}"
    end
  end

  def test_logout_returns_the_result_and_sends_the_idempotency_key
    http = Atlas::Test::StubRequester.new
    client = Atlas::Client.new("sk_test_123", http: http)
    http.enqueue(body: { "object" => "oauth_client_logout", "client_id" => "atlas_client_1", "sid" => "sess_1",
                         "session" => "already_ended", "grants_revoked" => 0, "backchannel_logouts" => 1 })
    out = client.oauth_clients.logout("oc_1", "sess_1", idempotency_key: "idem_1")
    assert_equal "idem_1", http.last.headers["idempotency-key"]
    assert_equal "already_ended", out["session"]
    assert_equal 1, out["backchannel_logouts"]
  end
end
