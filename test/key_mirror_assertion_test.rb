# frozen_string_literal: true

require_relative "test_helper"
require "openssl"

# The key mirror verifies key-pair assertions locally, with the server's refusal codes; a disabled row is refused.
class KeyMirrorAssertionTest < Minitest::Test
  class Keys
    def initialize(row) = @row = row
    def create(_body, idempotency_key: nil) = @row
  end

  def setup
    @key = OpenSSL::PKey::EC.generate("prime256v1")
    @offset = 0
    row = { "id" => "key_1", "subject_type" => "machine", "subject_id" => "m1", "scopes" => %w[read write], "secret" => nil,
            "credential" => "key_pair", "audience" => "ins_1", "public_key" => @key.public_to_pem }
    @store = Atlas::MemoryKeyMirrorStore.new
    @mirror = Atlas::KeyMirror.new(store: @store, api_keys: Keys.new(row), now: -> { (Time.now.to_f * 1000).to_i + @offset })
    @mirror.mint({})
  end

  def sign(**opts)
    Atlas.sign_api_key_assertion(@key.private_to_pem, "key_1", opts.delete(:audience) || "ins_1", **opts)
  end

  def test_valid_assertion_narrows_scope
    v = @mirror.verify_assertion(sign(scope: "read", jti: "a"), required_scopes: ["read"])
    assert v.valid?
    assert_equal "key_pair", v.credential
    assert_equal "a", v.jti
    assert_equal ["read"], v.effective_scopes
    assert_equal :scope_not_granted, @mirror.verify_assertion(sign(scope: "admin")).code
  end

  def test_refusal_codes_and_jti_claimed_last
    assert_equal :wrong_audience, @mirror.verify_assertion(sign(audience: "other")).code
    assert_equal :assertion_expired, @mirror.verify_assertion(sign(ttl_seconds: -100)).code
    assert_equal :assertion_lifetime_too_long, @mirror.verify_assertion(sign(ttl_seconds: 7200)).code
    assert_equal :invalid_assertion, @mirror.verify_assertion("a.b.c").code
    token = sign(jti: "j1")
    assert_equal :insufficient_scope, @mirror.verify_assertion(token, required_scopes: ["nope"]).code
    assert @mirror.verify_assertion(token).valid?
    assert_equal :assertion_replayed, @mirror.verify_assertion(token).code
    @offset = -600_000
    assert_equal :assertion_not_yet_valid, @mirror.verify_assertion(sign).code
  end

  def test_disabled_and_revoked_rows
    @store.get("key_1").enabled = false
    assert_equal :invalid_assertion, @mirror.verify_assertion(sign).code
    assert @mirror.apply_webhook({ "type" => "api_key.updated", "data" => { "id" => "key_1", "enabled" => true } })
    assert @mirror.verify_assertion(sign).valid?
    @store.mark_revoked("key_1", 1)
    refute @mirror.verify_assertion(sign).valid?
  end

  def test_secret_verify_refuses_a_disabled_row
    api = Keys.new({ "id" => "k2", "secret" => "ak_s", "enabled" => false })
    mirror = Atlas::KeyMirror.new(store: Atlas::MemoryKeyMirrorStore.new, api_keys: api)
    mirror.mint({})
    refute mirror.verify("ak_s").valid?
    mirror.apply_webhook({ "type" => "api_key.updated", "data" => { "id" => "k2", "enabled" => true } })
    assert mirror.verify("ak_s").valid?
  end
end
