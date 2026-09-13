# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"

# §7.3 local session-token verification. Signs real RS256 tokens with a test
# key, serves the matching public JWKS through the JwksCache +fetch_impl:+ seam,
# and asserts the verifier accepts a good session and rejects each way a token
# can be wrong. No network.
class VerifyTest < Minitest::Test
  ISSUER = "https://acme.atlas.dev"

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @jwk = JWT::JWK.new(@rsa)
    jwks_json = JSON.generate({ "keys" => [@jwk.export] })
    @fetch = ->(_url) { [200, jwks_json] }
  end

  def backend(authorized_parties: nil)
    Atlas::Backend.new(
      jwks_url: "https://acme.atlas.dev/v1/jwks",
      issuer: ISSUER,
      authorized_parties: authorized_parties,
      fetch_impl: @fetch,
    )
  end

  def sign(claims)
    now = Time.now.to_i
    payload = { "iss" => ISSUER, "sub" => "user_1", "iat" => now, "nbf" => now, "exp" => now + 3600 }.merge(claims)
    JWT.encode(payload, @rsa, "RS256", { kid: @jwk.kid })
  end

  def test_accepts_a_valid_session_token
    result = backend.verify(sign({ "sid" => "sess_1" }))
    assert result.ok?, "expected a valid token to verify, got #{result.reason.inspect}"
    assert_equal "user_1", result.claims["sub"]
    assert_equal "sess_1", result.claims["sid"]
  end

  def test_rejects_a_wrong_issuer
    token = sign({ "iss" => "https://evil.atlas.dev" })
    result = backend.verify(token)
    refute result.ok?
    assert_equal :invalid, result.reason
  end

  def test_rejects_an_expired_token
    now = Time.now.to_i
    token = JWT.encode(
      { "iss" => ISSUER, "sub" => "user_1", "iat" => now - 7200, "exp" => now - 3600 },
      @rsa, "RS256", { kid: @jwk.kid }
    )
    result = backend.verify(token)
    refute result.ok?
    assert_equal :invalid, result.reason
  end

  def test_rejects_a_tampered_signature
    good = sign({})
    header, payload, = good.split(".")
    tampered = "#{header}.#{payload}.AAAAtampered"
    result = backend.verify(tampered)
    refute result.ok?
  end

  def test_rejects_a_malformed_token
    assert_equal :malformed, backend.verify("not-a-jwt").reason
    assert_equal :malformed, backend.verify(nil).reason
  end

  def test_token_confusion_guard_rejects_an_id_or_access_token
    # An access/id token carries aud and/or token_use != "session".
    assert_equal :invalid, backend.verify(sign({ "aud" => "some-api" })).reason
    assert_equal :invalid, backend.verify(sign({ "token_use" => "access" })).reason
  end

  def test_authorized_parties_allowlist
    b = backend(authorized_parties: ["https://app.acme.com"])
    assert b.verify(sign({ "azp" => "https://app.acme.com" })).ok?

    bad = b.verify(sign({ "azp" => "https://phish.example" }))
    refute bad.ok?
    assert_equal :unauthorized_party, bad.reason
  end

  def test_protect_helper_on_a_verified_result
    claims = { "sub" => "user_1", "org_permissions" => ["org:billing:manage"] }
    result = Atlas::VerifyResult.success(claims)
    assert result.ok?
    assert result.has?(permission: "org:billing:manage")
    refute result.has?(permission: "org:billing:read")
  end
end
