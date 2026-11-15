# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"
require "base64"
require "digest"

class StatusListTest < Minitest::Test
  NOW_SEC = 1_800_000_000
  NOW = (NOW_SEC * 1000) + 10_000

  def b64(x) = Base64.urlsafe_encode64(x, padding: false)

  def rsa
    k = OpenSSL::PKey::RSA.generate(2048)
    [k, JSON.parse(JSON.generate(JWT::JWK.new(k, kid: "k1").export)).merge("alg" => "RS256", "use" => "sig")]
  end

  def ec
    k = OpenSSL::PKey::EC.generate("prime256v1")
    [k, JSON.parse(JSON.generate(JWT::JWK.new(k, kid: "k2").export)).merge("alg" => "ES256", "use" => "sig")]
  end

  def token(key, alg, kid, sids, over = {}, header = {})
    hashes = sids.map { |s| Digest::SHA256.digest(s).byteslice(0, 8) }.sort
    claims = { "iss" => "https://atlas.test", "sub" => "session-status-list", "aud" => "atlas:session-status-list",
               "token_use" => "session_status_list", "iat" => NOW_SEC, "nbf" => NOW_SEC - 5, "exp" => NOW_SEC + 120,
               "since" => (NOW_SEC - 3600) * 1000, "window_seconds" => 3600, "hash_bytes" => 8, "count" => hashes.length,
               "truncated" => false, "h" => b64(hashes.join) }.merge(over)
    head = b64(JSON.generate({ "alg" => alg, "kid" => kid, "typ" => "statuslist+jwt" }.merge(header)))
    body = b64(JSON.generate(claims))
    data = "#{head}.#{body}"
    sig = if alg == "RS256"
            key.sign("SHA256", data)
          else
            der = OpenSSL::ASN1.decode(key.sign("SHA256", data))
            der.value.map { |i| i.value.to_s(2).rjust(32, "\0") }.join
          end
    "#{data}.#{b64(sig)}"
  end

  def verify(tok, jwk, **opts) = Atlas::StatusList.verify_token(tok, jwks: { "keys" => [jwk] }, now: -> { NOW }, **opts)

  def reason(&block) = assert_raises(Atlas::StatusList::InvalidError, &block).reason

  def test_rs256_and_es256_and_empty
    key, jwk = rsa
    list = verify(token(key, "RS256", "k1", %w[sess_a sess_b sess_c]), jwk, issuer: "https://atlas.test")
    assert_equal 3, list.count
    %w[sess_a sess_b sess_c].each { |s| assert list.has?(s) }
    refute list.has?("sess_d")
    assert_equal (NOW_SEC + 120) * 1000, list.expires_at
    ekey, ejwk = ec
    empty = verify(token(ekey, "ES256", "k2", []), ejwk)
    assert_equal 0, empty.count
    refute empty.has?("anything")
  end

  def test_refusals
    key, jwk = rsa
    other, = rsa
    assert_equal :bad_signature, reason { verify(token(other, "RS256", "k1", ["a"]), jwk) }
    good = token(key, "RS256", "k1", ["a"])
    h, b, s = good.split(".")
    forged = JSON.parse(Base64.urlsafe_decode64(b + ("=" * ((4 - (b.length % 4)) % 4)))).merge("count" => 2)
    assert_equal :bad_signature, reason { verify("#{h}.#{b64(JSON.generate(forged))}.#{s}", jwk) }
    assert_equal :bad_claims, reason { verify(good, jwk, issuer: "https://other") }
    assert_equal :expired, reason { Atlas::StatusList.verify_token(good, jwks: { "keys" => [jwk] }, now: -> { (NOW_SEC + 1000) * 1000 }) }
    assert_equal :bad_claims, reason { verify(token(key, "RS256", "k1", ["a"], { "token_use" => "session" }), jwk) }
    assert_equal :unsupported, reason { verify(token(key, "RS256", "k1", ["a"], {}, { "typ" => "JWT" }), jwk) }
    assert_equal :no_key, reason { verify(token(key, "RS256", "zz", ["a"]), jwk) }
    assert_equal :malformed, reason { verify("nope", jwk) }
    assert verify(token(key, "RS256", "k1", ["a"], { "truncated" => true }), jwk).truncated
  end

  def checker(key, jwk, sids, over = {}, clock: nil, **opts)
    now = clock || -> { NOW }
    body = { "token" => token(key, "RS256", "k1", sids, over) }
    http = lambda do |_m, url, _h, _b|
      url.end_with?("/jwks") ? [200, JSON.generate("keys" => [jwk]), {}] : [200, JSON.generate(body), {}]
    end
    Atlas::StatusList::EdgeChecker.new(secret_key: "sk_test_x", jwks_url: "https://atlas.test/jwks", http: http, now: now, **opts)
  end

  def test_checker_verdicts
    key, jwk = rsa
    c = checker(key, jwk, ["sess_a"])
    assert_equal :revoked, c.check("sess_a")
    assert_equal :ok, c.check("sess_b")
    truncated = checker(key, jwk, ["sess_a"], { "truncated" => true })
    assert_equal :revoked, truncated.check("sess_a")
    assert_equal :unavailable, truncated.check("sess_b")
    down = Atlas::StatusList::EdgeChecker.new(secret_key: "sk_test_x", jwks_url: "https://x/jwks", http: ->(*) { [500, "{}", {}] }, now: -> { NOW })
    assert_equal :unavailable, down.check("s")
    allow = Atlas::StatusList::EdgeChecker.new(secret_key: "sk_test_x", jwks_url: "https://x/jwks", http: ->(*) { [500, "{}", {}] }, now: -> { NOW }, on_stale: :allow)
    assert_equal :ok, allow.check("s")
  end

  def test_sid_revocation_list_uses_the_status_list_and_falls_back_to_the_feed
    key, jwk = rsa
    calls = []
    http = lambda do |_m, url, _h, _b|
      calls << url
      if url.end_with?("/jwks") then [200, JSON.generate("keys" => [jwk]), {}]
      elsif url.include?("status-list") then [200, JSON.generate("token" => token(key, "RS256", "k1", ["sess_a"], { "truncated" => true })), {}]
      else [200, JSON.generate("data" => [{ "sid" => "sess_z", "revoked_at" => NOW }], "has_more" => false, "server_time" => NOW), {}]
      end
    end
    list = Atlas::SidRevocationList.new(secret_key: "sk_test_x", http: http, now: -> { NOW }, source: :status_list,
                                        jwks_url: "https://atlas.test/jwks", issuer: "https://atlas.test")
    assert list.revoked?("sess_a")            # named in the signed list
    assert list.revoked?("sess_z")            # truncated list does not clear it: the feed answers
    refute list.revoked?("sess_other")
    assert(calls.any? { |u| u.include?("/v1/sessions/revoked") })
  end

  def test_machine_keys_fail_clearly_without_openssl_3
    stub_const = OpenSSL::VERSION
    OpenSSL.send(:remove_const, :VERSION)
    OpenSSL.const_set(:VERSION, "2.2.0")
    err = assert_raises(Atlas::ConfigurationError) { Atlas::MachineClient.new(issuer: "https://x", store: Atlas::MemoryMachineStore.new) }
    assert_match(/openssl gem 3.0/, err.message)
  ensure
    OpenSSL.send(:remove_const, :VERSION)
    OpenSSL.const_set(:VERSION, stub_const)
  end
end
