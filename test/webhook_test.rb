# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "openssl"

class WebhookTest < Minitest::Test
  SECRET = "whsec_test_secret"
  NOW = 1_757_937_600_000
  BODY = JSON.generate({ id: "evt_1", type: "user.updated", data: { id: "user_1" } })

  def sign(id, ts, body, secret = SECRET)
    mac = OpenSSL::HMAC.digest("SHA256", secret, "#{id}.#{ts}.#{body}")
    { "Atlas-Id" => id, "Atlas-Timestamp" => ts.to_s, "Atlas-Signature" => "v1,#{Base64.strict_encode64(mac)}" }
  end

  def test_returns_the_delivery_id_and_timestamp
    result = Atlas::Webhook.verify(body: BODY, headers: sign("evt_1", NOW - 1000, BODY), secret: SECRET, now_ms: NOW)
    assert result.verified?
    assert_equal "evt_1", result.delivery_id
    assert_equal NOW - 1000, result.timestamp
    assert_equal "user.updated", result.event["type"]
  end

  def test_reads_rack_style_headers
    rack = sign("evt_1", NOW, BODY).to_h { |k, v| ["HTTP_#{k.upcase.tr('-', '_')}", v] }
    assert Atlas::Webhook.verify(body: BODY, headers: rack, secret: SECRET, now_ms: NOW).verified?
  end

  def test_rejections
    headers = sign("evt_1", NOW, BODY)
    tampered = Atlas::Webhook.verify(body: BODY.sub("user_1", "user_2"), headers: headers, secret: SECRET, now_ms: NOW)
    assert_equal :signature_mismatch, tampered.reason
    assert_nil tampered.delivery_id
    assert_equal :signature_mismatch,
                 Atlas::Webhook.verify(body: BODY, headers: sign("evt_1", NOW, BODY, "whsec_x"), secret: SECRET, now_ms: NOW).reason
    assert_equal :stale_timestamp,
                 Atlas::Webhook.verify(body: BODY, headers: sign("evt_1", NOW - 360_000, BODY), secret: SECRET, now_ms: NOW).reason
    assert_equal :stale_timestamp,
                 Atlas::Webhook.verify(body: BODY, headers: sign("evt_1", NOW + 360_000, BODY), secret: SECRET, now_ms: NOW).reason
    assert_equal :missing_headers, Atlas::Webhook.verify(body: BODY, headers: {}, secret: SECRET, now_ms: NOW).reason
    bad = headers.merge("Atlas-Signature" => "v2,abc")
    assert_equal :malformed_signature, Atlas::Webhook.verify(body: BODY, headers: bad, secret: SECRET, now_ms: NOW).reason
  end
end
