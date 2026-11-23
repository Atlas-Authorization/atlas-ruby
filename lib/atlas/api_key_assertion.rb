# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"

module Atlas
  # Sign the short-lived assertion a key-pair API key presents instead of a
  # secret. +private_key_pem+ is the PKCS#8 PEM Atlas returned once at create.
  # ES256 for P-256 keys (raw r || s), EdDSA for Ed25519 keys.
  def self.sign_api_key_assertion(private_key_pem, key_id, audience, ttl_seconds: 300, scope: nil, jti: nil)
    key = OpenSSL::PKey.read(private_key_pem)
    ed = key.respond_to?(:oid) && key.oid == "ED25519"
    now = Time.now.to_i
    claims = { iss: key_id, aud: audience, iat: now, exp: now + ttl_seconds, jti: jti || SecureRandom.urlsafe_base64(16) }
    claims[:scope] = scope if scope
    b64 = ->(s) { Base64.urlsafe_encode64(s, padding: false) }
    header = { alg: ed ? "EdDSA" : "ES256", kid: key_id, typ: "JWT" }
    input = "#{b64.call(JSON.generate(header))}.#{b64.call(JSON.generate(claims))}"
    sig = if ed
            key.sign(nil, input)
          else
            OpenSSL::ASN1.decode(key.sign("SHA256", input)).value.map { |i| i.value.to_s(2).rjust(32, "\0") }.join
          end
    "#{input}.#{b64.call(sig)}"
  end
end
