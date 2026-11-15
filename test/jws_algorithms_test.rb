# frozen_string_literal: true

require_relative "test_helper"
require "openssl"
require "base64"

# Instances may sign with RS256, ES256, ES384, PS256 or EdDSA: every verification path accepts all five, checks the
# key type against the alg, and refuses none and HS*.
class JwsAlgorithmsTest < Minitest::Test
  ISS = "https://auth.example.com"
  ALGS = %w[RS256 ES256 ES384 PS256 EdDSA].freeze

  def b64u(x) = Base64.urlsafe_encode64(x, padding: false)

  # A runtime key for +alg+: [private key, public JWK with kid].
  def keypair(alg, kid = "k1")
    case alg
    when "RS256", "PS256"
      k = OpenSSL::PKey::RSA.generate(2048)
      jwk = { "kty" => "RSA", "n" => b64u(k.n.to_s(2)), "e" => b64u(k.e.to_s(2)) }
    when "ES256", "ES384"
      curve = alg == "ES256" ? "prime256v1" : "secp384r1"
      k = OpenSSL::PKey::EC.generate(curve)
      pt = k.public_key.to_bn(:uncompressed).to_s(2)
      n = (pt.bytesize - 1) / 2
      jwk = { "kty" => "EC", "crv" => alg == "ES256" ? "P-256" : "P-384", "x" => b64u(pt.byteslice(1, n)), "y" => b64u(pt.byteslice(1 + n, n)) }
    else
      k = OpenSSL::PKey.generate_key("ED25519")
      jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => b64u(Atlas::Ed25519Raw.public_bytes(k)) }
    end
    [k, jwk.merge("kid" => kid, "use" => "sig")]
  end

  def sign(alg, key, claims, header = {})
    head = b64u(JSON.generate({ "alg" => alg, "kid" => "k1", "typ" => "JWT" }.merge(header)))
    data = "#{head}.#{b64u(JSON.generate(claims))}"
    sig =
      case alg
      when "RS256" then key.sign("SHA256", data)
      when "PS256" then key.sign_pss("SHA256", data, salt_length: 32, mgf1_hash: "SHA256")
      when "EdDSA" then key.sign(nil, data)
      else
        size = alg == "ES256" ? 32 : 48
        OpenSSL::ASN1.decode(key.sign(alg == "ES256" ? "SHA256" : "SHA384", data)).value.map { |i| i.value.to_s(2).rjust(size, "\0") }.join
      end
    "#{data}.#{b64u(sig)}"
  end

  def jwks_fetch(*jwks) = ->(_url) { [200, JSON.generate("keys" => jwks)] }

  def claims(extra = {})
    now = Time.now.to_i
    { "iss" => ISS, "sub" => "user_1", "sid" => "ses_1", "iat" => now, "exp" => now + 300 }.merge(extra)
  end

  def backend(jwk) = Atlas::Backend.new(jwks_url: "#{ISS}/v1/jwks", issuer: ISS, fetch_impl: jwks_fetch(jwk))

  def test_session_tokens_verify_with_every_algorithm
    ALGS.each do |alg|
      key, jwk = keypair(alg)
      assert backend(jwk).verify(sign(alg, key, claims)).ok?, "#{alg} session token"
    end
  end

  def test_session_tokens_refuse_none_hs_and_key_confusion
    key, jwk = keypair("RS256")
    b = backend(jwk)
    unsigned = "#{b64u(JSON.generate('alg' => 'none', 'kid' => 'k1'))}.#{b64u(JSON.generate(claims))}."
    refute b.verify(unsigned).ok?
    # HS256 signed with the public key bytes as the secret (the classic confusion attack)
    head = b64u(JSON.generate("alg" => "HS256", "kid" => "k1"))
    data = "#{head}.#{b64u(JSON.generate(claims))}"
    hs = "#{data}.#{b64u(OpenSSL::HMAC.digest('SHA256', key.public_to_pem, data))}"
    refute b.verify(hs).ok?
    %w[HS384 HS512 PS512 RS512].each do |alg|
      refute b.verify("#{b64u(JSON.generate('alg' => alg, 'kid' => 'k1'))}.#{b64u(JSON.generate(claims))}.#{b64u('x' * 32)}").ok?
    end
    # an ES256 token against an RSA key (type does not fit the alg), and an EdDSA one against an EC key
    ekey, = keypair("ES256")
    refute b.verify(sign("ES256", ekey, claims)).ok?
    _, ec_jwk = keypair("ES256")
    edkey, = keypair("EdDSA")
    refute backend(ec_jwk).verify(sign("EdDSA", edkey, claims)).ok?
    # right key type, wrong key
    other, = keypair("RS256")
    refute b.verify(sign("RS256", other, claims)).ok?
    # a JWK pinned to another alg is not used
    refute backend(jwk.merge("alg" => "PS256")).verify(sign("RS256", key, claims)).ok?
    # P-256 key cannot verify an ES384 token
    k384, = keypair("ES384")
    _, jwk256 = keypair("ES256")
    refute backend(jwk256).verify(sign("ES384", k384, claims)).ok?
  end

  def test_expired_and_wrong_issuer_still_refused
    key, jwk = keypair("EdDSA")
    refute backend(jwk).verify(sign("EdDSA", key, claims("exp" => Time.now.to_i - 100))).ok?
    refute backend(jwk).verify(sign("EdDSA", key, claims("iss" => "https://evil.example"))).ok?
  end

  def test_id_tokens_verify_with_every_algorithm_and_refuse_the_rest
    ALGS.each do |alg|
      key, jwk = keypair(alg)
      http = lambda do |_m, url, _h, _b|
        if url.end_with?("/jwks") then [200, JSON.generate("keys" => [jwk]), {}]
        else [200, JSON.generate("issuer" => ISS, "authorization_endpoint" => "#{ISS}/a", "token_endpoint" => "#{ISS}/t", "jwks_uri" => "#{ISS}/jwks"), {}]
        end
      end
      flow = Atlas::OIDC::Flow.new(issuer: ISS, client_id: "app", redirect_uri: "https://app.example.com/cb", secret: "s" * 40, http: http)
      id = sign(alg, key, claims("aud" => "app", "nonce" => "n1"))
      assert_equal "user_1", flow.verify_id_token(id, nonce: "n1")["sub"], "#{alg} id token"
    end
    key, jwk = keypair("RS256")
    http = lambda do |_m, url, _h, _b|
      url.end_with?("/jwks") ? [200, JSON.generate("keys" => [jwk]), {}] : [200, JSON.generate("issuer" => ISS, "authorization_endpoint" => "#{ISS}/a", "token_endpoint" => "#{ISS}/t", "jwks_uri" => "#{ISS}/jwks"), {}]
    end
    flow = Atlas::OIDC::Flow.new(issuer: ISS, client_id: "app", redirect_uri: "https://app.example.com/cb", secret: "s" * 40, http: http)
    none = "#{b64u(JSON.generate('alg' => 'none'))}.#{b64u(JSON.generate(claims('aud' => 'app', 'nonce' => 'n1')))}."
    assert_raises(Atlas::OIDC::Error) { flow.verify_id_token(none, nonce: "n1") }
    hs = "#{b64u(JSON.generate('alg' => 'HS256', 'kid' => 'k1'))}.#{b64u(JSON.generate(claims('aud' => 'app', 'nonce' => 'n1')))}.#{b64u('x' * 32)}"
    assert_raises(Atlas::OIDC::Error) { flow.verify_id_token(hs, nonce: "n1") }
    assert_raises(Atlas::OIDC::Error) { flow.verify_id_token(sign("RS256", key, claims("aud" => "other", "nonce" => "n1")), nonce: "n1") }
  end

  def test_access_tokens_logout_tokens_and_transaction_tokens
    ALGS.each do |alg|
      key, jwk = keypair(alg)
      fetch = jwks_fetch(jwk)
      access = Atlas::AccessTokenVerifier.new(issuer: ISS, audience: "api", jwks_url: "#{ISS}/jwks", fetch_impl: fetch)
      at = sign(alg, key, claims("aud" => "api", "token_use" => "access_token"))
      assert access.verify("Bearer #{at}").ok?, "#{alg} access token"
      refute access.verify("Bearer #{at.split('.')[0..1].join('.')}.#{b64u('x' * 64)}").ok?
      logout = Atlas::BackchannelLogout.new(issuer: ISS, jwks_url: "#{ISS}/jwks", client_id: "app", fetch_impl: fetch)
      tok = sign(alg, key, { "iss" => ISS, "aud" => "app", "iat" => Time.now.to_i, "jti" => "j#{alg}", "sub" => "u", "sid" => "s",
                              "events" => { Atlas::BackchannelLogout::EVENT => {} } }, "typ" => "logout+jwt")
      assert_equal "s", logout.verify(tok).sid, "#{alg} logout token"
      none = "#{b64u(JSON.generate('alg' => 'none', 'typ' => 'logout+jwt'))}.#{b64u(JSON.generate('iss' => ISS))}."
      assert_raises(Atlas::InvalidLogoutTokenError) { logout.verify(none) }

      txn = sign(alg, key, { "iss" => ISS, "aud" => "example.com", "sub" => "u", "iat" => Time.now.to_i, "exp" => Time.now.to_i + 60,
                              "txn" => "t", "scope" => "a", "req_wl" => "w" }, "typ" => "txntoken+jwt")
      assert Atlas.verify_transaction_token(txn, issuer: ISS, trust_domain: "example.com", jwks: { "keys" => [jwk] }).ok?, "#{alg} txn token"
    end
  end
end
