# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"

# OIDC Back-Channel Logout token verification, with a test RSA key served
# through the JWKS fetch seam. No network.
class BackchannelLogoutTest < Minitest::Test
  ISSUER = "https://atlasauth.net"
  CLIENT_ID = "aid_client_1"
  EVENT = "http://schemas.openid.net/event/backchannel-logout"

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @jwk = JWT::JWK.new(@rsa)
    jwks_json = JSON.generate({ "keys" => [@jwk.export] })
    @fetch = ->(_url) { [200, jwks_json] }
    @now = Time.now.to_i
  end

  def verifier(**opts)
    Atlas::BackchannelLogout.new(
      issuer: ISSUER, jwks_url: "#{ISSUER}/.well-known/jwks.json", client_id: CLIENT_ID,
      fetch_impl: @fetch, now: -> { @now }, **opts
    )
  end

  def claims(overrides = {})
    {
      "iss" => ISSUER, "aud" => CLIENT_ID, "sub" => "user_1", "sid" => "sess_1",
      "iat" => @now, "exp" => @now + 120, "jti" => "jti_#{rand(1_000_000)}",
      "events" => { EVENT => {} }
    }.merge(overrides)
  end

  def sign(payload, typ: "logout+jwt", key: @rsa, kid: @jwk.kid, alg: "RS256")
    header = { kid: kid }
    header[:typ] = typ if typ
    payload = payload.reject { |_, v| v == :omit }
    JWT.encode(payload, key, alg, header)
  end

  def assert_rejected(token, reason, **opts)
    error = assert_raises(Atlas::InvalidLogoutTokenError) { verifier(**opts).verify(token) }
    assert_equal reason, error.reason
  end

  def test_accepts_a_valid_logout_token
    result = verifier.verify(sign(claims("jti" => "jti_ok")))
    assert_equal "user_1", result.sub
    assert_equal "sess_1", result.sid
    assert_equal "jti_ok", result.jti
    assert_equal @now, result.iat
  end

  def test_accepts_sub_only_and_missing_typ_and_array_aud
    result = verifier.verify(sign(claims("sid" => :omit, "aud" => ["other", CLIENT_ID]), typ: nil))
    assert_nil result.sid
    assert_equal "user_1", result.sub
  end

  def test_rejects_wrong_typ
    assert_rejected sign(claims, typ: "JWT"), :wrong_type
  end

  def test_rejects_a_nonce
    assert_rejected sign(claims("nonce" => "n")), :nonce_present
  end

  def test_rejects_missing_events
    assert_rejected sign(claims("events" => :omit)), :missing_claim
    assert_rejected sign(claims("events" => { "other" => {} })), :missing_claim
  end

  def test_rejects_an_event_value_that_is_not_an_object
    assert_rejected sign(claims("events" => { EVENT => "yes" })), :invalid_claim
  end

  def test_rejects_wrong_audience
    assert_rejected sign(claims("aud" => "someone_else")), :wrong_audience
  end

  def test_rejects_wrong_issuer
    assert_rejected sign(claims("iss" => "https://evil.example")), :wrong_issuer
  end

  def test_rejects_expired
    assert_rejected sign(claims("iat" => @now - 600, "exp" => @now - 300)), :expired
  end

  def test_rejects_old_token_without_exp
    assert_rejected sign(claims("exp" => :omit, "iat" => @now - 3600)), :expired
  end

  def test_rejects_iat_in_the_future_and_missing_iat
    assert_rejected sign(claims("iat" => @now + 3600, "exp" => @now + 7200)), :issued_in_future
    assert_rejected sign(claims("iat" => :omit)), :missing_claim
  end

  def test_rejects_missing_jti_and_missing_sub_and_sid
    assert_rejected sign(claims("jti" => :omit)), :missing_claim
    assert_rejected sign(claims("sub" => :omit, "sid" => :omit)), :missing_claim
  end

  def test_rejects_a_bad_signature
    other = OpenSSL::PKey::RSA.generate(2048)
    assert_rejected sign(claims, key: other), :invalid_signature
  end

  def test_rejects_hs256_and_garbage
    assert_rejected JWT.encode(claims, "secret", "HS256", { kid: @jwk.kid, typ: "logout+jwt" }), :invalid_signature
    assert_rejected "not-a-jwt", :malformed
  end

  def test_jti_store_blocks_replays
    store = Atlas::MemoryJtiStore.new(now: -> { @now })
    token = sign(claims("jti" => "once"))
    verifier(jti_store: store).verify(token)
    assert_rejected token, :replayed, jti_store: store
  end

  def test_unreachable_jwks_is_no_keys_and_retryable
    @fetch = ->(_url) { raise Errno::ECONNREFUSED }
    error = assert_raises(Atlas::InvalidLogoutTokenError) { verifier.verify(sign(claims)) }
    assert_equal :no_keys, error.reason
    assert error.retryable?
  end

  def test_jwks_5xx_is_retryable
    @fetch = ->(_url) { [503, "down"] }
    error = assert_raises(Atlas::InvalidLogoutTokenError) { verifier.verify(sign(claims)) }
    assert error.retryable?
  end

  def test_a_bad_token_is_not_retryable
    error = assert_raises(Atlas::InvalidLogoutTokenError) { verifier.verify(sign(claims("aud" => "other"))) }
    refute error.retryable?
    error = assert_raises(Atlas::InvalidLogoutTokenError) { verifier.verify("not-a-jwt") }
    refute error.retryable?
  end
end
