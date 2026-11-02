# frozen_string_literal: true

require_relative "test_helper"

# The 0.23.0 additions: preflight acknowledgements, the OAuth client secret
# reveal, require_verified_email / client_secret on client writes, platform app
# lookups, invitation expiry, the before_user_create fail_closed switch and the
# new webhook event names.
class PreflightAcksSecretRevealTest < Minitest::Test
  OPS = [
    ["GET", "/v1/instance/preflight/acks", nil, ->(c) { c.instance.list_preflight_acks }],
    ["PUT", "/v1/instance/preflight/acks/pkce_not_required", { "reason" => "legacy app", "expires_at" => 1_900_000_000_000 },
     ->(c) { c.instance.acknowledge_preflight("pkce_not_required", reason: "legacy app", expires_at: 1_900_000_000_000) }],
    ["PUT", "/v1/instance/preflight/acks/a%2Fb?dry_run=true", { "reason" => "r" },
     ->(c) { c.instance.acknowledge_preflight("a/b", reason: "r", dry_run: true) }],
    ["DELETE", "/v1/instance/preflight/acks/pkce_not_required", nil, ->(c) { c.instance.delete_preflight_ack("pkce_not_required") }],
    ["POST", "/v1/oauth_clients/oc_1/secret/reveal", nil, ->(c) { c.oauth_clients.reveal_secret("oc_1") }],
    ["POST", "/v1/oauth_clients", { "name" => "App", "client_secret" => "s" * 40, "require_verified_email" => true },
     ->(c) { c.oauth_clients.create({ name: "App", client_secret: "s" * 40, require_verified_email: true }) }],
    ["PATCH", "/v1/oauth_clients/oc_1", { "require_verified_email" => false },
     ->(c) { c.oauth_clients.update("oc_1", { require_verified_email: false }) }],
    ["GET", "/v1/platform/apps?name_prefix=acme&external_ref=crm%2F1&limit=50", nil,
     ->(c) { c.platform.apps.list({ name_prefix: "acme", external_ref: "crm/1", limit: 50 }) }],
    ["POST", "/v1/invitations", { "email_address" => "a@example.com", "expires_in_days" => 30 },
     ->(c) { c.invitations.create({ email_address: "a@example.com", expires_in_days: 30 }) }],
    ["PATCH", "/v1/instance/hooks/before_user_create", { "fail_closed" => true },
     ->(c) { c.user_hooks.update_before_user_create({ fail_closed: true }) }]
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
        assert(req.body.nil? || req.body.empty?, "#{verb} #{path} sends no body")
      else
        assert_equal body, JSON.parse(req.body), "#{verb} #{path}"
      end
    end
  end

  def test_reveal_returns_the_secret
    http = Atlas::Test::StubRequester.new
    client = Atlas::Client.new("sk_test_123", http: http)
    http.enqueue(body: { "object" => "oauth_client_secret", "id" => "oc_1", "client_id" => "atlas_client_1",
                         "client_secret" => "sec", "secret_prefix" => "se", "client_secret_expires_at" => nil, "note" => "n" })
    assert_equal "sec", client.oauth_clients.reveal_secret("oc_1")["client_secret"]
  end

  def test_event_constants
    assert_equal "session.expired", Atlas::WEBHOOK_EVENT_SESSION_EXPIRED
    assert_equal "invitation.created", Atlas::WEBHOOK_EVENT_INVITATION_CREATED
    assert_equal "invitation.accepted", Atlas::WEBHOOK_EVENT_INVITATION_ACCEPTED
    assert_equal "invitation.revoked", Atlas::WEBHOOK_EVENT_INVITATION_REVOKED
  end
end
