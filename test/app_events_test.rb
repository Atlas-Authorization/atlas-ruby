# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "openssl"

class AppEventsTest < Minitest::Test
  KEY = "app-webhook-signing-key-32bytes!"
  SECRET = "whsec_#{Base64.strict_encode64(KEY)}".freeze
  NOW = Time.at(1_761_782_400)
  BODY = JSON.generate({ type: "call.completed", data: { call_id: "c1" } })

  def sig(id, ts, body, key = KEY)
    "v1,#{Base64.strict_encode64(OpenSSL::HMAC.digest('SHA256', key, "#{id}.#{ts}.#{body}"))}"
  end

  def headers(id, ts, signature)
    { "Webhook-Id" => id, "Webhook-Timestamp" => ts.to_s, "Webhook-Signature" => signature }
  end

  def verify(hdrs, body = BODY)
    Atlas::Webhook.verify_standard(body: body, headers: hdrs, secret: SECRET, now: NOW)
  end

  def test_verifies_a_signed_delivery
    ts = NOW.to_i - 10
    result = verify(headers("msg_1", ts, sig("msg_1", ts, BODY)))
    assert result.verified?
    assert_equal "msg_1", result.delivery_id
    assert_equal ts, result.timestamp
    assert_equal "call.completed", result.event["type"]
  end

  # The published Standard Webhooks test vector.
  def test_standard_webhooks_vector
    result = Atlas::Webhook.verify_standard(
      body: '{"test": 2432232314}',
      headers: headers("msg_p5jXN8AQM9LWM0D4loKWxJek", 1_614_265_330, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="),
      secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
      now: Time.at(1_614_265_330)
    )
    assert result.verified?, result.reason.inspect
  end

  def test_rotation_second_signature_valid
    ts = NOW.to_i
    both = "#{sig('msg_1', ts, BODY, 'old-key')} #{sig('msg_1', ts, BODY)}"
    assert verify(headers("msg_1", ts, both)).verified?
  end

  def test_rejections
    ts = NOW.to_i
    assert_equal :signature_mismatch, verify(headers("msg_1", ts, sig("msg_1", ts, BODY, "wrong-key"))).reason
    assert_equal :signature_mismatch, verify(headers("msg_1", ts, sig("msg_1", ts, BODY)), BODY.sub("c1", "c2")).reason
    assert_equal :stale_timestamp, verify(headers("msg_1", ts - 301, sig("msg_1", ts - 301, BODY))).reason
    assert_equal :stale_timestamp, verify(headers("msg_1", "#{ts}.5", sig("msg_1", ts, BODY))).reason
    assert_equal :missing_headers, verify(headers("msg_1", ts, sig("msg_1", ts, BODY)).except("Webhook-Signature")).reason
    assert_equal :malformed_signature, verify(headers("msg_1", ts, "v2,abc v1,")).reason
  end

  def test_create_browser_ticket_minimal_body
    http = Atlas::Test::StubRequester.new
    http.enqueue(body: { "object" => "browser_ticket" })
    Atlas::Client.new("sk_test_123", http: http).sessions.create_browser_ticket("user_1")
    assert_equal({ "user_id" => "user_1", "mode" => "browser_ticket" }, JSON.parse(http.last.body))
  end
end
