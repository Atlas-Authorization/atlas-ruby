# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"
require "securerandom"

# DPoP (RFC 9449) on the access-token verifier: the same vectors as the
# TypeScript @atlasauth/backend suite, plus every other refusal path. Keys are
# generated per run; proofs are genuine ES256 / RS256 / PS256 / EdDSA JWSs.
class DPoPTest < Minitest::Test
  ISSUER = "https://auth.example.com"
  API = "https://api.example.com/mcp"
  META = "https://api.example.com/.well-known/oauth-protected-resource/mcp"

  # A client key and the proofs it signs, built with OpenSSL directly so the
  # proof format is independent of the code under test.
  class Key
    attr_reader :alg, :jwk, :jkt

    def initialize(alg = "ES256")
      @alg = alg
      case alg
      when "ES256"
        @pkey = OpenSSL::PKey::EC.generate("prime256v1")
        pt = @pkey.public_key.to_octet_string(:uncompressed)
        @jwk = { "kty" => "EC", "crv" => "P-256", "x" => b64(pt.byteslice(1, 32)), "y" => b64(pt.byteslice(33, 32)) }
      when "RS256", "PS256"
        @pkey = OpenSSL::PKey::RSA.generate(2048)
        @jwk = { "kty" => "RSA", "n" => b64(@pkey.n.to_s(2)), "e" => b64(@pkey.e.to_s(2)) }
      else
        @pkey = OpenSSL::PKey.generate_key("ED25519")
        @jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => b64(@pkey.public_to_der.byteslice(-32, 32)) }
      end
      @jkt = Atlas::DPoP.jwk_thumbprint(@jwk)
    end

    def b64(raw) = Base64.urlsafe_encode64(raw, padding: false)

    def sign(input)
      case @alg
      when "ES256"
        asn = OpenSSL::ASN1.decode(@pkey.sign(OpenSSL::Digest.new("SHA256"), input))
        asn.value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join
      when "RS256" then @pkey.sign(OpenSSL::Digest.new("SHA256"), input)
      when "PS256" then @pkey.sign_pss("SHA256", input, salt_length: :digest, mgf1_hash: "SHA256")
      else @pkey.sign(nil, input)
      end
    end

    def proof(token, header: nil, alg: @alg, iat: Time.now.to_i, tamper: false, **claims)
      body = { "htm" => "POST", "htu" => API, "jti" => SecureRandom.hex(8), "iat" => iat,
               "ath" => Atlas::DPoP.access_token_hash(token) }
      claims.each { |k, v| v.nil? ? body.delete(k.to_s) : body[k.to_s] = v }
      body.delete("iat") if iat.nil?
      h = header || { "typ" => "dpop+jwt", "alg" => alg, "jwk" => @jwk }
      input = "#{b64(JSON.generate(h))}.#{b64(JSON.generate(body))}"
      sig = sign(input)
      input = "#{b64(JSON.generate(h))}.#{b64(JSON.generate({ 'htm' => 'POST', 'jti' => 'x' }))}" if tamper
      "#{input}.#{b64(sig)}"
    end
  end

  def setup
    @as = OpenSSL::PKey::EC.generate("prime256v1")
    as_jwk = JWT::JWK.new(@as)
    @kid = as_jwk.kid
    jwks = JSON.generate({ "keys" => [as_jwk.export.merge(alg: "ES256")] })
    @fetch = ->(_url) { [200, jwks] }
  end

  def token(jkt = nil)
    now = Time.now.to_i
    claims = { "iss" => ISSUER, "sub" => "user_1", "aud" => API, "exp" => now + 300, "token_use" => "access_token",
               "scope" => "tools:read", "client_id" => "cli_1", "jti" => SecureRandom.hex(6) }
    claims["cnf"] = { "jkt" => jkt } if jkt
    JWT.encode(claims, @as, "ES256", { kid: @kid })
  end

  def verifier(**opts)
    Atlas::AccessTokenVerifier.new(issuer: ISSUER, audience: API, fetch_impl: @fetch, resource_metadata_url: META, **opts)
  end

  def check(v, scheme, tok, proof, method: "POST", url: "#{API}?x=1")
    v.verify("#{scheme} #{tok}", method: method, url: url, dpop: proof)
  end

  def assert_refused(result, error, name = error)
    refute result.ok?, name
    assert_equal 401, result.status, name
    assert_equal error, result.error, "#{name}: #{result.description}"
    assert result.www_authenticate.start_with?("DPoP "), name
    assert_includes result.www_authenticate, "error=\"#{error}\""
    assert_includes result.www_authenticate, 'algs="ES256'
  end

  def test_accepts_bound_token_with_matching_proof_for_every_alg
    v = verifier
    %w[ES256 RS256 PS256 EdDSA].each do |alg|
      k = Key.new(alg)
      tok = token(k.jkt)
      r = check(v, "DPoP", tok, k.proof(tok))
      assert r.ok?, "#{alg}: #{r.description}"
      assert r.dpop_bound?
      assert_equal "user_1", r.subject
    end
    plain = check(v, "Bearer", token, nil)
    assert plain.ok?
    refute plain.dpop_bound?
  end

  def test_never_accepts_bound_token_as_bearer
    k = Key.new
    tok = token(k.jkt)
    assert_refused check(verifier, "Bearer", tok, k.proof(tok)), "invalid_token"
    assert_refused verifier.verify("DPoP #{tok}"), "invalid_dpop_proof"
    unbound = token
    assert_refused check(verifier, "DPoP", unbound, k.proof(unbound)), "invalid_token"
  end

  def test_rejects_every_bad_proof
    v = verifier(dpop_replay_store: Atlas::DPoP::MemoryReplayStore.new)
    k = Key.new
    other = Key.new
    tok = token(k.jkt)
    now = Time.now.to_i
    cases = {
      "missing proof" => nil,
      "malformed" => "not-a-jwt",
      "garbage header" => "e30.e30.e30",
      "another key" => other.proof(tok),
      "wrong htm" => k.proof(tok, htm: "GET"),
      "wrong htu" => k.proof(tok, htu: "https://api.example.com/other"),
      "wrong host" => k.proof(tok, htu: "https://evil.example.com/mcp"),
      "relative htu" => k.proof(tok, htu: "/mcp"),
      "wrong ath" => k.proof(tok, ath: "nope"),
      "no ath" => k.proof(tok, ath: nil),
      "proof for another token" => k.proof(token(k.jkt)),
      "stale" => k.proof(tok, iat: now - 3600),
      "future" => k.proof(tok, iat: now + 60),
      "no iat" => k.proof(tok, iat: nil),
      "expired exp" => k.proof(tok, exp: now - 60),
      "no jti" => k.proof(tok, jti: nil),
      "typ JWT" => k.proof(tok, header: { "typ" => "JWT", "alg" => "ES256", "jwk" => k.jwk }),
      "alg HS256" => k.proof(tok, header: { "typ" => "dpop+jwt", "alg" => "HS256", "jwk" => k.jwk }),
      "alg none" => k.proof(tok, header: { "typ" => "dpop+jwt", "alg" => "none", "jwk" => k.jwk }),
      "no jwk" => k.proof(tok, header: { "typ" => "dpop+jwt", "alg" => "ES256" }),
      "private jwk" => k.proof(tok, header: { "typ" => "dpop+jwt", "alg" => "ES256", "jwk" => k.jwk.merge("d" => "AAAA") }),
      "alg/key mismatch" => Key.new("RS256").proof(tok, header: { "typ" => "dpop+jwt", "alg" => "RS256", "jwk" => k.jwk }),
      "bad signature" => k.proof(tok, tamper: true)
    }
    cases.each { |name, proof| assert_refused check(v, "DPoP", tok, proof), "invalid_dpop_proof", name }

    once = k.proof(tok, jti: "fixed")
    assert check(v, "DPoP", tok, once).ok?
    assert_refused check(v, "DPoP", tok, once), "invalid_dpop_proof", "replay"
    tok_other = token(other.jkt)
    assert check(v, "DPoP", tok_other, other.proof(tok_other, jti: "fixed")).ok?, "same jti, other key"
  end

  def test_require_dpop_refuses_unbound_token
    v = verifier(require_dpop: true)
    assert_refused check(v, "Bearer", token, nil), "invalid_token"
    none = v.verify(nil)
    assert_equal 401, none.status
    assert_nil none.error
    assert_match(/\ADPoP .*algs="/, none.www_authenticate)
  end

  def test_htu_normalisation_and_public_origin
    k = Key.new
    tok = token(k.jkt)
    v = verifier
    ["HTTPS://API.Example.COM:443/mcp", "https://api.example.com/mcp?other=2#frag"].each do |htu|
      assert check(v, "DPoP", tok, k.proof(tok, htu: htu)).ok?, htu
    end
    assert_refused check(v, "DPoP", tok, k.proof(tok), url: "/mcp?x=1"), "invalid_dpop_proof"
    vo = verifier(public_origin: "https://api.example.com")
    assert check(vo, "DPoP", tok, k.proof(tok), url: "/mcp?x=1", method: "post").ok?
    {
      "https://A.example.com:443" => "https://a.example.com/",
      "http://a.example.com:80/x?y#z" => "http://a.example.com/x",
      "https://a.example.com:8443/p/" => "https://a.example.com:8443/p/",
      "https://[::1]:443/p" => "https://[::1]/p"
    }.each { |given, want| assert_equal want, Atlas::DPoP.normalize_htu(given), given }
    assert_nil Atlas::DPoP.normalize_htu("ftp://x/y")
  end

  def test_server_nonce
    clock = [Time.now.to_f]
    nonces = Atlas::DPoP::HmacNonceSource.new("s" * 32, window_seconds: 60, now: -> { clock[0] })
    v = verifier(dpop_nonces: nonces)
    k = Key.new
    tok = token(k.jkt)
    r = check(v, "DPoP", tok, k.proof(tok))
    assert_refused r, "use_dpop_nonce"
    assert_equal nonces.current, r.dpop_nonce
    assert_refused check(v, "DPoP", tok, k.proof(tok, nonce: "made-up")), "use_dpop_nonce"
    ok = check(v, "DPoP", tok, k.proof(tok, nonce: r.dpop_nonce))
    assert ok.ok?, ok.description
    refute_nil ok.dpop_nonce
    issued = nonces.current
    clock[0] += 60
    assert nonces.valid?(issued)
    clock[0] += 60
    refute nonces.valid?(issued)
    assert_refused check(v, "DPoP", tok, k.proof(tok, nonce: issued)), "use_dpop_nonce"
    assert_raises(ArgumentError) { Atlas::DPoP::HmacNonceSource.new("short") }
  end

  def test_helpers
    n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    assert_equal "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                 Atlas::DPoP.jwk_thumbprint({ "kty" => "RSA", "e" => "AQAB", "alg" => "RS256", "kid" => "2011-04-29", "n" => n })
    assert_raises(ArgumentError) { Atlas::DPoP.jwk_thumbprint({ "kty" => "oct", "k" => "x" }) }
    clock = [1000.0]
    store = Atlas::DPoP::MemoryReplayStore.new(max_entries: 2, now: -> { clock[0] })
    assert store.claim("a", 1060)
    refute store.claim("a", 1060)
    clock[0] = 1120
    assert store.claim("a", 1180)
    store.claim("b", 1180)
    store.claim("c", 1180)
    assert_operator store.size, :<=, 2
    doc = Atlas.protected_resource_metadata(resource: API, issuer: ISSUER, dpop_bound_access_tokens_required: true)
    assert_equal true, doc["dpop_bound_access_tokens_required"]
    assert_equal Atlas::DPoP::ALGS, doc["dpop_signing_alg_values_supported"]
    assert_equal "DPoP error=\"use_dpop_nonce\", error_description=\"n\", algs=\"#{Atlas::DPoP::ALGS.join(' ')}\"",
                 Atlas.build_www_authenticate(scheme: "DPoP", error: "use_dpop_nonce", description: "n")
  end

  def test_rack_guard_dpop_with_nonce
    nonces = Atlas::DPoP::HmacNonceSource.new("k" * 32)
    v = verifier(dpop_nonces: nonces)
    k = Key.new("EdDSA")
    tok = token(k.jkt)
    app = ->(env) { [200, { "content-type" => "text/plain" }, [env["atlas.access_token"].dpop_bound?.to_s]] }
    guard = Atlas::AccessTokenGuard.new(app, verifier: v)
    env = lambda do |proof|
      { "REQUEST_METHOD" => "PUT", "SCRIPT_NAME" => "", "PATH_INFO" => "/docs/1", "QUERY_STRING" => "draft=1",
        "rack.url_scheme" => "https", "HTTP_HOST" => "api.example.com",
        "HTTP_AUTHORIZATION" => "DPoP #{tok}", "HTTP_DPOP" => proof }
    end
    proof = ->(nonce, jti) { k.proof(tok, htm: "PUT", htu: "https://api.example.com/docs/1", nonce: nonce, jti: jti) }
    status, headers, = guard.call(env.call(proof.call(nil, "a")))
    assert_equal 401, status
    nonce = headers["dpop-nonce"]
    refute_nil nonce
    assert headers["www-authenticate"].start_with?('DPoP error="use_dpop_nonce"')
    status, headers, body = guard.call(env.call(proof.call(nonce, "b")))
    assert_equal 200, status
    assert_equal ["true"], body
    refute_nil headers["dpop-nonce"]
    status, headers, = guard.call(env.call(proof.call(nonce, "b")))
    assert_equal 401, status
    assert_includes headers["www-authenticate"], 'error="invalid_dpop_proof"'
    two = env.call("#{proof.call(nonce, 'c')}, #{proof.call(nonce, 'd')}")
    assert_equal 401, guard.call(two)[0]
  end
end
