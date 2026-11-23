# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "openssl"

# Key-pair API key assertions: header, claims, and a signature that verifies
# with the public key.
class ApiKeyAssertionTest < Minitest::Test
  def parts(jwt)
    h, c, s = jwt.split(".")
    [JSON.parse(Base64.urlsafe_decode64(h)), JSON.parse(Base64.urlsafe_decode64(c)), "#{h}.#{c}", Base64.urlsafe_decode64(s)]
  end

  def test_es256_is_raw_rs_and_verifies
    key = OpenSSL::PKey::EC.generate("prime256v1")
    jwt = Atlas.sign_api_key_assertion(key.private_to_pem, "key_1", "ins_1", scope: "read", jti: "j1")
    header, claims, input, sig = parts(jwt)
    assert_equal({ "alg" => "ES256", "kid" => "key_1", "typ" => "JWT" }, header)
    assert_equal %w[key_1 ins_1 read j1], claims.values_at("iss", "aud", "scope", "jti")
    assert_equal 300, claims["exp"] - claims["iat"]
    assert_equal 64, sig.bytesize
    der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(0, 32), 2)),
                                   OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(32, 32), 2))]).to_der
    assert key.verify("SHA256", der, input)
  end

  def test_eddsa_verifies
    key = OpenSSL::PKey.generate_key("ED25519")
    jwt = Atlas.sign_api_key_assertion(key.private_to_pem, "key_2", "ins_1", ttl_seconds: 60)
    header, claims, input, sig = parts(jwt)
    assert_equal "EdDSA", header["alg"]
    assert_equal 60, claims["exp"] - claims["iat"]
    refute_empty claims["jti"]
    assert key.verify(nil, sig, input)
  end
end
