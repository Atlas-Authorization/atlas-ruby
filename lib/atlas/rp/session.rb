# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"

module Atlas
  module RP
    # Your own app session, kept in one sealed (AES-256-GCM), httpOnly cookie: no server-side store to run.
    # It holds what the relying party needs to keep the Atlas session alive and to sign out: the user, the
    # Atlas +sid+, the ID token (the logout hint) and +touched_at+.
    #
    #   session = Atlas::RP::Session.new(secret: ENV["SESSION_SECRET"])
    #   cookie  = session.build({ "sub" => "user_1", "sid" => "ses_1" })   # a Set-Cookie value
    #   session.read(request_cookie_header)                                # => Hash or nil
    #
    # Keep the cookie small (browsers refuse over 4 KB): +store_id_token: false+ drops the ID token.
    class Session
      PREFIX = "r1."

      attr_reader :name

      def initialize(secret:, name: "atlas_session", max_age: 7 * 86_400, secure: true, same_site: "Lax",
                     path: "/", domain: nil, now: nil)
        raise ArgumentError, "Session: `secret` (at least 32 characters) is required." if secret.to_s.length < 32

        @key = OpenSSL::KDF.hkdf(secret, salt: "atlas-rp-session", info: "v1", length: 32, hash: "SHA256")
        @name = name
        @max_age = max_age
        @secure = secure
        @same_site = same_site
        @path = path
        @domain = domain
        @now = now
      end

      # @return [String] a +Set-Cookie+ value carrying +data+ (a JSON-able Hash).
      def build(data)
        payload = data.merge("exp" => clock + @max_age)
        cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
        cipher.key = @key
        iv = SecureRandom.random_bytes(12)
        cipher.iv = iv
        sealed = cipher.update(JSON.generate(payload)) + cipher.final + cipher.auth_tag(16)
        cookie("#{PREFIX}#{b64u(iv)}.#{b64u(sealed)}", @max_age)
      end

      # @param header [String, nil] the request's +Cookie+ header.
      # @return [Hash, nil] the session data (string keys), or nil when absent, forged, or expired.
      def read(header)
        raw = cookie_value(header)
        return nil unless raw&.start_with?(PREFIX)

        iv, data = raw[PREFIX.length..].split(".", 2)
        return nil unless iv && data

        bytes = b64u_decode(data)
        return nil if bytes.bytesize < 17

        cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
        cipher.key = @key
        cipher.iv = b64u_decode(iv)
        cipher.auth_tag = bytes.byteslice(-16, 16)
        parsed = JSON.parse(cipher.update(bytes.byteslice(0, bytes.bytesize - 16)) + cipher.final)
        return nil unless parsed.is_a?(Hash) && parsed["exp"].is_a?(Numeric) && parsed["exp"] > clock

        parsed
      rescue StandardError
        nil
      end

      # @return [String] a +Set-Cookie+ value that removes the session cookie.
      def clear
        cookie("", 0)
      end

      private

      def cookie(value, max_age)
        parts = ["#{@name}=#{value}", "Path=#{@path}", "Max-Age=#{max_age}", "HttpOnly", "SameSite=#{@same_site}"]
        parts << "Domain=#{@domain}" if @domain
        parts << "Expires=Thu, 01 Jan 1970 00:00:00 GMT" if max_age.zero?
        parts << "Secure" if @secure
        parts.join("; ")
      end

      def cookie_value(header)
        header.to_s.split(";").each do |part|
          k, v = part.split("=", 2)
          return v.strip if v && k.strip == @name
        end
        nil
      end

      def clock = (@now ? @now.call : Time.now).to_i
      def b64u(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
      def b64u_decode(str) = Base64.urlsafe_decode64(str + ("=" * ((4 - (str.length % 4)) % 4)))
    end
  end
end
