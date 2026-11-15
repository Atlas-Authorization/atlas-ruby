# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

module Atlas
  # Signature and claim verification for the JWTs Atlas issues (session tokens, access tokens, ID tokens, logout
  # tokens, transaction tokens, status lists). An instance may sign with RS256, ES256, ES384, PS256 or EdDSA; all five
  # are accepted, the key's type (and curve) must fit the header's +alg+, and +none+ and every HS* algorithm are
  # refused before any key is looked at. Uses OpenSSL only (no EdDSA gem).
  module JWS
    ALGORITHMS = %w[RS256 ES256 ES384 PS256 EdDSA].freeze
    KEY_TYPES = { "RS256" => ["RSA", nil], "PS256" => ["RSA", nil], "ES256" => ["EC", "P-256"], "ES384" => ["EC", "P-384"],
                  "EdDSA" => ["OKP", "Ed25519"] }.freeze
    CURVE_OIDS = { "P-256" => "prime256v1", "P-384" => "secp384r1" }.freeze

    # Any token that must not be trusted. Subclasses say which check failed.
    class Error < StandardError; end
    class MalformedError < Error; end
    class AlgorithmError < Error; end
    class NoKeyError < Error; end
    class VerificationError < Error; end
    class ExpiredError < Error; end
    class NotYetValidError < Error; end
    class InvalidIssuerError < Error; end
    class InvalidAudienceError < Error; end
    class MissingClaimError < Error; end

    module_function

    def b64u_decode(str)
      raise MalformedError, "not base64url" unless str.is_a?(String) && str.match?(/\A[A-Za-z0-9_-]*\z/)

      Base64.urlsafe_decode64(str + ("=" * ((4 - (str.length % 4)) % 4)))
    end

    # The decoded JOSE header, without verifying anything.
    def header_of(token)
      parts = token.to_s.split(".", -1)
      raise MalformedError, "not a JWT" unless parts.length == 3 && !parts[0].empty?

      h = JSON.parse(b64u_decode(parts[0]))
      raise MalformedError, "bad header" unless h.is_a?(Hash)

      h
    rescue JSON::ParserError
      raise MalformedError, "bad header"
    end

    # Verify the signature and the registered claims.
    #
    # @param keys [Hash] a JWKS: +{ "keys" => [...] }+.
    # @param algorithms [Array<String>] accepted algorithms (a subset of {ALGORITHMS}).
    # @param iss [String, Array<String>, nil] accepted issuer(s); nil skips the check.
    # @param aud [String, nil] required audience (+aud+ may be a string or an array containing it).
    # @param leeway [Numeric] clock skew, seconds. @param now [#call, nil] clock returning epoch seconds.
    # @param verify_exp [Boolean] check +exp+ / +nbf+ when present. @param required [Array<String>] claims that must exist.
    # @return [Array(Hash, Hash)] +[payload, header]+
    # @raise [Atlas::JWS::Error]
    def decode(token, keys, algorithms: ALGORITHMS, iss: nil, aud: nil, leeway: 0, now: nil, verify_exp: true, required: [])
      header = header_of(token)
      alg = header["alg"]
      raise AlgorithmError, "algorithm #{alg.inspect} is not accepted" unless alg.is_a?(String) && algorithms.include?(alg) && ALGORITHMS.include?(alg)

      parts = token.split(".", -1)
      sig = b64u_decode(parts[2])
      jwk = candidates(keys, alg, header["kid"]).find { |k| verify_signature(alg, k, "#{parts[0]}.#{parts[1]}", sig) }
      raise VerificationError, "signature does not verify" unless jwk

      payload = JSON.parse(b64u_decode(parts[1]))
      raise MalformedError, "payload is not an object" unless payload.is_a?(Hash)

      check_claims(payload, iss: iss, aud: aud, leeway: leeway, now: now, verify_exp: verify_exp, required: required)
      [payload, header]
    rescue JSON::ParserError
      raise MalformedError, "bad payload"
    end

    # Keys that could have signed a token with +alg+ and +kid+: matching type and curve, matching +kid+ when the token
    # names one, and not pinned to a different +alg+.
    def candidates(keys, alg, kid)
      kty, crv = KEY_TYPES.fetch(alg)
      list = Array(keys && (keys["keys"] || keys[:keys])).select { |k| k.is_a?(Hash) }.map { |k| k.transform_keys(&:to_s) }.select do |k|
         k["kty"] == kty && (crv.nil? || k["crv"] == crv) && (k["alg"].nil? || k["alg"] == alg) &&
          (k["use"].nil? || k["use"] == "sig") && (kid.nil? || k["kid"] == kid)
      end
      raise NoKeyError, "no published key fits #{alg}#{kid ? " (kid #{kid})" : ''}" if list.empty?

      list
    end

    def check_claims(payload, iss:, aud:, leeway:, now:, verify_exp:, required:)
      required.each { |c| raise MissingClaimError, "missing #{c}" unless payload.key?(c) }
      if iss
        accepted = Array(iss).map { |i| i.to_s.sub(%r{/+\z}, "") }
        raise InvalidIssuerError, "issuer #{payload['iss'].inspect} not accepted" unless payload["iss"].is_a?(String) && accepted.include?(payload["iss"].sub(%r{/+\z}, ""))
      end
      if aud
        raise InvalidAudienceError, "audience does not include #{aud}" unless Array(payload["aud"]).include?(aud)
      end
      return unless verify_exp

      t = (now ? now.call : Time.now.to_i)
      raise ExpiredError, "token expired" if payload["exp"].is_a?(Numeric) && payload["exp"] + leeway <= t
      raise NotYetValidError, "token not yet valid" if payload["nbf"].is_a?(Numeric) && payload["nbf"] - leeway > t
    end

    def verify_signature(alg, jwk, data, sig)
      key = public_key(jwk)
      case alg
      when "RS256" then key.verify("SHA256", sig, data)
      when "PS256" then key.verify_pss("SHA256", sig, data, salt_length: 32, mgf1_hash: "SHA256")
      when "EdDSA" then key.verify(nil, sig, data)
      else
        size = alg == "ES256" ? 32 : 48
        return false unless sig.bytesize == size * 2

        der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(0, size), 2)),
                                       OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(size, size), 2))]).to_der
        key.verify(alg == "ES256" ? "SHA256" : "SHA384", der, data)
      end
    rescue OpenSSL::OpenSSLError, ArgumentError, MalformedError
      false
    end

    # An OpenSSL public key from a JWK (RSA, EC P-256/P-384, OKP Ed25519).
    def public_key(jwk)
      spki =
        case jwk["kty"]
        when "RSA"
          rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(bn(jwk["n"])), OpenSSL::ASN1::Integer(bn(jwk["e"]))]).to_der
          OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null.new(nil)]),
                                   OpenSSL::ASN1::BitString(rsa)]).to_der
        when "EC"
          oid = CURVE_OIDS.fetch(jwk["crv"])
          size = jwk["crv"] == "P-256" ? 32 : 48
          x = b64u_decode(jwk["x"]).rjust(size, "\0")
          y = b64u_decode(jwk["y"]).rjust(size, "\0")
          OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"), OpenSSL::ASN1::ObjectId(oid)]),
                                   OpenSSL::ASN1::BitString("\x04".b + x + y)]).to_der
        when "OKP"
          raise ArgumentError, "only Ed25519" unless jwk["crv"] == "Ed25519"

          ["302a300506032b6570032100"].pack("H*") + b64u_decode(jwk["x"])
        else raise ArgumentError, "unsupported key type"
        end
      OpenSSL::PKey.read(spki)
    rescue ::KeyError
      raise ArgumentError, "unsupported curve"
    end

    def bn(str) = OpenSSL::BN.new(b64u_decode(str), 2)
  end
end
