# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "openssl"
require "uri"

module Atlas
  # DPoP proof verification (RFC 9449) for {AccessTokenVerifier}.
  #
  # A DPoP-bound access token carries +cnf.jkt+, the RFC 7638 thumbprint of the
  # client's key. Each request must then arrive with the +DPoP+ scheme and a
  # +DPoP+ header: a short-lived JWT (+typ+ +dpop+jwt+) signed by that key,
  # carrying the public key itself, the request method (+htm+) and URL (+htu+),
  # the hash of the access token (+ath+), a unique +jti+, and the server's
  # nonce when the API asks for one.
  module DPoP
    # How old a DPoP proof may be.
    PROOF_MAX_AGE_SECONDS = 300
    # Clock skew tolerated on a proof's +iat+.
    CLOCK_SKEW = 5
    # The JWS algorithms accepted on a DPoP proof (and advertised in challenges / metadata).
    ALGS = %w[ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA].freeze
    PRIVATE_MEMBERS = %w[d k p q dp dq qi].freeze
    EC_CURVES = {
      "ES256" => ["P-256", "prime256v1", 32, "SHA256"],
      "ES384" => ["P-384", "secp384r1", 48, "SHA384"],
      "ES512" => ["P-521", "secp521r1", 66, "SHA512"]
    }.freeze

    # The in-process replay store: entries live until they expire, at most
    # +max_entries+. Any object with +claim(key, expires_at) -> Boolean+ (epoch
    # seconds; false when already seen) works in its place — share one (Redis
    # +SET NX EX+, a unique database key) when the API runs in several processes.
    class MemoryReplayStore
      def initialize(max_entries: 10_000, now: nil)
        @max = max_entries.positive? ? max_entries : 10_000
        @now = now || -> { Time.now.to_f }
        @seen = {}
        @lock = Mutex.new
      end

      def claim(key, expires_at)
        @lock.synchronize do
          now = @now.call
          return false if (@seen[key] || 0) > now

          @seen[key] = expires_at
          if @seen.size > @max
            @seen.delete_if { |_, exp| exp <= now }
            while @seen.size > @max
              oldest = @seen.reject { |k, _| k == key }.min_by { |_, exp| exp }
              break if oldest.nil?

              @seen.delete(oldest[0])
            end
          end
          true
        end
      end

      def size
        @seen.size
      end
    end

    # Server nonces (RFC 9449 §8) derived from a secret and the clock: a nonce
    # is good for the window it was issued in and the next one, so every
    # process sharing the secret agrees without shared state. Any object with
    # +current -> String+ and +valid?(nonce) -> Boolean+ works in its place.
    class HmacNonceSource
      def initialize(secret, window_seconds: 300, now: nil)
        raise ArgumentError, "The DPoP nonce secret must be at least 32 bytes" if secret.to_s.bytesize < 32

        @secret = secret.to_s.b
        @window = window_seconds.positive? ? window_seconds : 300
        @now = now || -> { Time.now.to_f }
      end

      def current
        at(epoch)
      end

      def valid?(nonce)
        return false unless nonce.is_a?(String)

        e = epoch
        [at(e), at(e - 1)].any? { |c| DPoP.secure_compare(c, nonce) }
      end

      private

      def epoch
        (@now.call / @window).floor
      end

      def at(epoch)
        DPoP.b64u(OpenSSL::HMAC.digest("SHA256", @secret, "atlas-dpop-nonce:".b + [epoch].pack("q>")))
      end
    end

    module_function

    def b64u(raw)
      Base64.urlsafe_encode64(raw, padding: false)
    end

    def b64u_decode(value)
      raise ArgumentError, "bad base64url" unless value.is_a?(String) && value.match?(/\A[A-Za-z0-9_-]*\z/)

      Base64.urlsafe_decode64(value + ("=" * ((4 - (value.length % 4)) % 4)))
    end

    def secure_compare(a, b)
      a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
    end

    # The +ath+ a DPoP proof carries for +token+: base64url(SHA-256(token)).
    def access_token_hash(token)
      b64u(Digest::SHA256.digest(token))
    end

    # The RFC 7638 SHA-256 thumbprint (base64url) of a public EC, RSA or OKP
    # JWK: the +cnf.jkt+ a DPoP-bound token carries.
    def jwk_thumbprint(jwk)
      members = { "EC" => %w[crv kty x y], "RSA" => %w[e kty n], "OKP" => %w[crv kty x] }[jwk["kty"]]
      raise ArgumentError, "Unsupported JWK kty #{jwk['kty'].inspect}" if members.nil?

      parts = members.map do |m|
        v = jwk[m]
        raise ArgumentError, "JWK member #{m} is missing" unless v.is_a?(String) && !v.empty?

        "#{JSON.generate(m)}:#{JSON.generate(v)}"
      end
      b64u(Digest::SHA256.digest("{#{parts.join(',')}}"))
    end

    # Reduce a URL to the form RFC 9449 §4.3 compares +htu+ in: scheme and host
    # lower-cased, the default port dropped, an empty path as "/", no query or
    # fragment. nil for anything but an absolute http(s) URL.
    def normalize_htu(url)
      return nil unless url.is_a?(String)

      u = URI.parse(url)
      scheme = u.scheme.to_s.downcase
      return nil unless %w[http https].include?(scheme) && u.host && !u.host.empty?

      host = u.host.downcase
      host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
      port = u.port
      default = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
      host = "#{host}:#{port}" if port && !default
      path = u.path.to_s.empty? ? "/" : u.path
      "#{scheme}://#{host}#{path}"
    rescue URI::Error
      nil
    end

    # Check one proof. nil when it is good, else +[error, description]+ with
    # error +invalid_dpop_proof+ or +use_dpop_nonce+.
    def check_proof(proof, token:, jkt:, method:, url:, public_origin:, now:, replay:, nonces:)
      bad = ->(desc) { ["invalid_dpop_proof", desc] }
      parts = proof.split(".", -1)
      return bad.call("The DPoP proof is malformed.") unless parts.length == 3

      header = begin
        JSON.parse(b64u_decode(parts[0]))
      rescue StandardError
        nil
      end
      return bad.call("The DPoP proof is malformed.") unless header.is_a?(Hash)
      return bad.call("The DPoP proof must have typ dpop+jwt.") unless header["typ"] == "dpop+jwt"

      alg = header["alg"]
      return bad.call("The DPoP proof uses an unsupported algorithm.") unless ALGS.include?(alg)

      jwk = header["jwk"]
      return bad.call("The DPoP proof must carry its public key.") unless jwk.is_a?(Hash)
      return bad.call("The DPoP proof key must be a public key.") if PRIVATE_MEMBERS.any? { |m| jwk.key?(m) }

      sig = begin
        b64u_decode(parts[2])
      rescue StandardError
        nil
      end
      unless sig && verify_signature(jwk, alg, "#{parts[0]}.#{parts[1]}", sig)
        return bad.call("The DPoP proof signature is invalid.")
      end

      payload = begin
        JSON.parse(b64u_decode(parts[1]))
      rescue StandardError
        nil
      end
      return bad.call("The DPoP proof is malformed.") unless payload.is_a?(Hash)

      thumb = begin
        jwk_thumbprint(jwk)
      rescue ArgumentError
        ""
      end
      unless !thumb.empty? && secure_compare(thumb, jkt)
        return bad.call("The DPoP proof key does not match the token binding.")
      end
      return bad.call("The DPoP proof htm does not match the request method.") unless payload["htm"] == method

      target = url.to_s
      unless target.match?(%r{\Ahttps?://}i)
        target = public_origin ? join_url(public_origin, target) : nil
      end
      expected = target && normalize_htu(target)
      htu = payload["htu"]
      if expected.nil? || !htu.is_a?(String) || normalize_htu(htu) != expected
        return bad.call("The DPoP proof htu does not match the request URL.")
      end

      iat = payload["iat"]
      if !iat.is_a?(Numeric) || iat > now + CLOCK_SKEW || now - iat > PROOF_MAX_AGE_SECONDS
        return bad.call("The DPoP proof is too old or from the future.")
      end

      exp = payload["exp"]
      return bad.call("The DPoP proof is too old or from the future.") if exp.is_a?(Numeric) && now >= exp + CLOCK_SKEW
      unless payload["ath"] == access_token_hash(token)
        return bad.call("The DPoP proof ath does not match the access token.")
      end

      jti = payload["jti"]
      return bad.call("The DPoP proof needs a jti.") unless jti.is_a?(String) && !jti.empty?

      if nonces
        nonce = payload["nonce"]
        unless nonce.is_a?(String) && !nonce.empty? && nonces.valid?(nonce)
          return ["use_dpop_nonce", "The DPoP proof must carry the nonce from the DPoP-Nonce header."]
        end
      end
      return bad.call("The DPoP proof has already been used.") unless replay.claim("#{jkt}:#{jti}", iat + PROOF_MAX_AGE_SECONDS)

      nil
    end

    def join_url(origin, path)
      URI.join(origin, path).to_s
    rescue URI::Error
      nil
    end

    def verify_signature(jwk, alg, input, sig)
      return false if jwk["alg"].is_a?(String) && !jwk["alg"].empty? && jwk["alg"] != alg

      if (curve = EC_CURVES[alg])
        crv, ossl_curve, size, digest = curve
        return false unless jwk["kty"] == "EC" && jwk["crv"] == crv && sig.bytesize == 2 * size

        x = b64u_decode(jwk["x"].to_s)
        y = b64u_decode(jwk["y"].to_s)
        return false unless x.bytesize == size && y.bytesize == size

        key = OpenSSL::PKey.read(spki(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                                                                OpenSSL::ASN1::ObjectId(ossl_curve)]),
                                      "\x04".b + x + y))
        der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(0, size), 2)),
                                       OpenSSL::ASN1::Integer(OpenSSL::BN.new(sig.byteslice(size, size), 2))]).to_der
        key.verify(OpenSSL::Digest.new(digest), der, input)
      elsif alg.start_with?("RS", "PS")
        return false unless jwk["kty"] == "RSA"

        n = OpenSSL::BN.new(b64u_decode(jwk["n"].to_s), 2)
        e = OpenSSL::BN.new(b64u_decode(jwk["e"].to_s), 2)
        return false if n.num_bits < 2048 || e.to_i < 3

        key = OpenSSL::PKey.read(spki(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null.new(nil)]),
                                      OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der))
        digest = "SHA#{alg[2..]}"
        if alg.start_with?("PS")
          key.verify_pss(digest, sig, input, salt_length: :digest, mgf1_hash: digest)
        else
          key.verify(OpenSSL::Digest.new(digest), sig, input)
        end
      elsif alg == "EdDSA"
        return false unless jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519"

        x = b64u_decode(jwk["x"].to_s)
        return false unless x.bytesize == 32

        key = OpenSSL::PKey.read(spki(OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("1.3.101.112")]), x))
        key.verify(nil, sig, input)
      else
        false
      end
    rescue StandardError
      false
    end

    def spki(algorithm, key_bytes)
      OpenSSL::ASN1::Sequence([algorithm, OpenSSL::ASN1::BitString(key_bytes)]).to_der
    end
  end
end
