# frozen_string_literal: true

require "json"
require "base64"
require "openssl"
require "securerandom"

module Atlas
  # Vercel BotID for Atlas: the signing half that runs next to your BotID check.
  #
  # BotID's verdict (+checkBotId()+) only exists inside a Vercel-hosted request,
  # so that route turns it into a short signed attestation; the browser sends it
  # to Atlas as +captcha_token+, and Atlas checks the signature, freshness and
  # +is_bot == false+, and spends it (each attestation passes once). The same
  # secret is stored in Atlas for the +vercel_botid+ captcha provider.
  #
  # Format (version 1): +atlas_botid.v1.<payload>.<sig>+ — +payload+ is base64url
  # JSON +{v: 1, is_bot, verified_bot, iat, exp, jti}+; +sig+ is base64url
  # HMAC-SHA256 over +atlas_botid.v1.<payload>+ keyed by the shared secret.
  module BotId
    PREFIX = "atlas_botid.v1."
    MAX_TTL_SECONDS = 300
    SECRET_MIN_LENGTH = 32

    # Sign a BotID verdict for Atlas. Raises +ArgumentError+ when the secret is
    # shorter than 32 characters. A bot verdict is still signed — Atlas refuses
    # it. +ttl_seconds+ is clamped to 1–300.
    def self.create_attestation(secret, is_bot:, verified_bot: false, ttl_seconds: 60, now: nil)
      if !secret.is_a?(String) || secret.length < SECRET_MIN_LENGTH
        raise ArgumentError, "The BotID attestation secret must be at least #{SECRET_MIN_LENGTH} characters."
      end

      ttl = ttl_seconds.to_i.clamp(1, MAX_TTL_SECONDS)
      iat = (now || Time.now.to_i).to_i
      payload = b64u(JSON.generate({ v: 1, is_bot: is_bot ? true : false, verified_bot: verified_bot ? true : false,
                                     iat: iat, exp: iat + ttl, jti: b64u(SecureRandom.random_bytes(18)) }))
      sig = OpenSSL::HMAC.digest("SHA256", secret, PREFIX + payload)
      "#{PREFIX}#{payload}.#{b64u(sig)}"
    end

    def self.b64u(raw)
      Base64.urlsafe_encode64(raw, padding: false)
    end
    private_class_method :b64u
  end
end
