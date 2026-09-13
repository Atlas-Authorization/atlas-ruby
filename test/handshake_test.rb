# frozen_string_literal: true

require_relative "test_helper"
require "base64"
require "digest"

# Cross-property SSO handshake helpers. Exercises the nonce-redeem POST through
# the Transport +http:+ seam (no network) and the return-URL param parsing.
class HandshakeTest < Minitest::Test
  def test_reads_params_from_a_full_url
    params = Atlas.read_handshake_params(
      "https://sat.example.com/callback?__atlas_hs=ok&__atlas_hu=user_123&__atlas_hn=nonce_abc"
    )
    assert_equal({ user_id: "user_123", nonce: "nonce_abc" }, params)
  end

  def test_reads_params_from_a_bare_query_string
    assert_equal({ user_id: "u1", nonce: "n1" },
                 Atlas.read_handshake_params("__atlas_hs=ok&__atlas_hu=u1&__atlas_hn=n1"))
  end

  def test_nil_when_marker_absent_or_wrong
    assert_nil Atlas.read_handshake_params("?__atlas_hu=u1&__atlas_hn=n1")
    assert_nil Atlas.read_handshake_params("?__atlas_hs=nope&__atlas_hu=u1&__atlas_hn=n1")
  end

  def test_nil_when_user_or_nonce_missing
    assert_nil Atlas.read_handshake_params("?__atlas_hs=ok&__atlas_hu=u1")
    assert_nil Atlas.read_handshake_params("?__atlas_hs=ok&__atlas_hn=n1")
  end

  def test_nil_on_nil_or_empty_input
    assert_nil Atlas.read_handshake_params(nil)
    assert_nil Atlas.read_handshake_params("")
  end

  def test_redeems_a_nonce_for_a_session
    http = Atlas::Test::StubRequester.new.enqueue(
      status: 200,
      body: { jwt: "jwt_val", refresh_token: "rt_val", session_id: "sess_1", expires_in: 3600 }
    )

    session = Atlas.redeem_handshake(
      fapi_origin: "https://id.atlasauth.net/",
      publishable_key: "pk_test_1",
      user_id: "user_123",
      nonce: "nonce_abc",
      code_verifier: "verifier_xyz",
      http: http
    )

    assert_instance_of Atlas::HandshakeSession, session
    assert_equal "jwt_val", session.jwt
    assert_equal "rt_val", session.refresh_token
    assert_equal "sess_1", session.session_id
    assert_equal 3600, session.expires_in

    req = http.last
    assert_equal "POST", req.method
    assert_equal "https://id.atlasauth.net/v1/client/handshake/redeem", req.url
    assert_equal "pk_test_1", req.headers["x-publishable-key"]
    assert_equal(
      { "user_id" => "user_123", "nonce" => "nonce_abc", "code_verifier" => "verifier_xyz" },
      JSON.parse(req.body)
    )
  end

  def test_redeem_sends_code_verifier_in_the_json_body
    http = Atlas::Test::StubRequester.new.enqueue(
      status: 200,
      body: { jwt: "j", refresh_token: "r" }
    )

    Atlas.redeem_handshake(
      fapi_origin: "https://id.atlasauth.net",
      publishable_key: "pk_test_1",
      user_id: "u",
      nonce: "n",
      code_verifier: "the_secret_verifier",
      http: http
    )

    body = JSON.parse(http.last.body)
    assert_equal "the_secret_verifier", body["code_verifier"]
  end

  def test_create_pkce_pair_challenge_is_s256_of_verifier
    pair = Atlas.create_pkce_pair

    assert pair[:verifier].is_a?(String) && !pair[:verifier].empty?
    assert pair[:challenge].is_a?(String) && !pair[:challenge].empty?

    # S256: challenge == base64url-no-pad( SHA256(verifier) ).
    expected = Base64.urlsafe_encode64(Digest::SHA256.digest(pair[:verifier]), padding: false)
    assert_equal expected, pair[:challenge]

    # URL-safe, unpadded — RFC 7636 §3 forbids "+", "/" and trailing "=".
    refute_match(/[+\/=]/, pair[:verifier])
    refute_match(/[+\/=]/, pair[:challenge])
  end

  def test_create_pkce_pair_is_fresh_each_call
    refute_equal Atlas.create_pkce_pair[:verifier], Atlas.create_pkce_pair[:verifier]
  end

  def test_returns_nil_on_non_2xx
    http = Atlas::Test::StubRequester.new.enqueue(status: 401, body: {})
    assert_nil redeem(http)
  end

  def test_returns_nil_when_response_lacks_tokens
    http = Atlas::Test::StubRequester.new.enqueue(status: 200, body: { jwt: "only_jwt" })
    assert_nil redeem(http)
  end

  def test_returns_nil_and_does_not_raise_on_transport_error
    boom = ->(_m, _u, _h, _b) { raise "connection reset" }
    assert_nil redeem(boom)
  end

  def redeem(http)
    Atlas.redeem_handshake(
      fapi_origin: "https://x.example.com",
      publishable_key: "pk_test_1",
      user_id: "u",
      nonce: "n",
      http: http
    )
  end
end
