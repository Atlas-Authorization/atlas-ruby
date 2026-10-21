# frozen_string_literal: true

require_relative "test_helper"

# The trusted reverse proxy secret, and secret rotation with an overlap for
# webhook endpoints, per-instance platform keys and Sign in with Atlas apps.
class ProxySecretRotationTest < Minitest::Test
  BASE = "https://api.atlasauth.net"
  VIEW = { "object" => "proxy_secret", "set" => true, "created_at" => 1_800_000_000_000, "previous_expires_at" => nil,
           "secret_header" => "X-Atlas-Proxy-Secret", "client_ip_header" => "X-Atlas-Client-IP" }.freeze

  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
    @platform = Atlas::Client.new("psk_test_1", http: @http).platform
  end

  def test_proxy_secret_get_create_rotate_delete
    @http.enqueue(body: VIEW)
    assert_equal "X-Atlas-Client-IP", @client.instance_security.get_proxy_secret["client_ip_header"]
    assert_equal "GET", @http.last.method
    assert_equal "#{BASE}/v1/instance/proxy_secret", @http.last.url

    @http.enqueue(status: 201, body: VIEW.merge("secret" => "aps_1", "rotated" => false))
    assert_equal "aps_1", @client.instance_security.create_proxy_secret["secret"]
    assert_equal "POST", @http.last.method
    assert_nil @http.last.body

    @http.enqueue(body: VIEW.merge("secret" => "aps_2", "rotated" => true, "previous_expires_at" => 1_800_003_600_000))
    out = @client.instance_security.create_proxy_secret({ overlap_seconds: 3600 })
    assert_equal({ "overlap_seconds" => 3600 }, JSON.parse(@http.last.body))
    assert out["rotated"]
    assert_equal 1_800_003_600_000, out["previous_expires_at"]

    @http.enqueue(body: { "object" => "proxy_secret", "deleted" => true })
    assert @client.instance_security.delete_proxy_secret["deleted"]
    assert_equal "DELETE", @http.last.method
    assert_equal "#{BASE}/v1/instance/proxy_secret", @http.last.url
  end

  def test_webhook_rotate_secret_with_overlap
    @http.enqueue(body: { "object" => "webhook_secret", "secret" => "whsec_new", "overlap_seconds" => 600,
                          "previous_secret_expires_at" => 1_800_000_600_000 })
    out = @client.webhooks.endpoints.rotate_secret("whep_1", { overlap_seconds: 600 })
    assert_equal "#{BASE}/v1/webhook_endpoints/whep_1/rotate_secret", @http.last.url
    assert_equal({ "overlap_seconds" => 600 }, JSON.parse(@http.last.body))
    assert_equal 1_800_000_600_000, out["previous_secret_expires_at"]

    @http.enqueue(body: { "object" => "webhook_secret", "secret" => "whsec_2" })
    @client.webhooks.endpoints.rotate_secret("whep_1")
    assert_nil @http.last.body
  end

  def test_platform_instance_rotation_with_overlap
    @http.enqueue(body: { "object" => "app_secret", "app_id" => "app_1", "instance_id" => "ins_1", "secret" => "sk_x",
                          "overlap_seconds" => 0, "previous_keys_expire_at" => nil })
    out = @platform.apps.rotate_instance_secret("app_1", "ins_1", { overlap_seconds: 0 }, idempotency_key: "idem_1")
    req = @http.last
    assert_equal "#{BASE}/v1/platform/apps/app_1/instances/ins_1/rotate_secret", req.url
    assert_equal({ "overlap_seconds" => 0 }, JSON.parse(req.body))
    assert_equal "idem_1", req.headers["idempotency-key"]
    assert_equal "ins_1", out["instance_id"]

    @http.enqueue(body: { "object" => "app_secret", "app_id" => "app_1" })
    @platform.apps.rotate_instance_secret("app_1", "ins_1", idempotency_key: "idem_2")
    assert_nil @http.last.body
    assert_equal "idem_2", @http.last.headers["idempotency-key"]
  end

  def test_atlas_id_app_rotations_with_overlap
    @http.enqueue(body: { "object" => "atlas_id_app", "id" => "aia_1", "client_secret" => "cs_new",
                          "previous_secret_expires_at" => 1_800_003_600_000, "secret_issued_at" => 1_800_000_000_000 })
    out = @platform.atlas_id_apps.rotate_secret("aia_1", { overlap_seconds: 3600 })
    assert_equal "#{BASE}/v1/platform/atlas_id_apps/aia_1/rotate_secret", @http.last.url
    assert_equal({ "overlap_seconds" => 3600 }, JSON.parse(@http.last.body))
    assert_equal 1_800_000_000_000, out["secret_issued_at"]

    @http.enqueue(body: { "object" => "atlas_id_app", "id" => "aia_1", "webhook_secret" => "whsec_new",
                          "webhook_previous_secret_expires_at" => 1_800_000_600_000 })
    hook = @platform.atlas_id_apps.rotate_webhook_secret("aia_1", { overlap_seconds: 600 })
    assert_equal "#{BASE}/v1/platform/atlas_id_apps/aia_1/webhook/rotate_secret", @http.last.url
    assert_equal({ "overlap_seconds" => 600 }, JSON.parse(@http.last.body))
    assert_equal 1_800_000_600_000, hook["webhook_previous_secret_expires_at"]

    @http.enqueue(body: { "object" => "atlas_id_app", "id" => "aia_1" })
    @platform.atlas_id_apps.rotate_webhook_secret("aia_1")
    assert_nil @http.last.body
  end
end
