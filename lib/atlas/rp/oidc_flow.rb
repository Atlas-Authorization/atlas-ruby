# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"
require "uri"

require_relative "../error"
require_relative "../jwks_cache"
require_relative "../transport"
require_relative "../oidc_claims"
require_relative "../jws"

module Atlas
  module OIDC
    # A sign-in that failed. +code+ is one of +:state_mismatch+, +:issuer_mismatch+,
    # +:invalid_request+, +:invalid_token+, +:token_exchange_failed+, +:access_denied+,
    # +:discovery_failed+, +:reauthentication_required+, +:subject_mismatch+.
    # +clear_cookie+ is a +Set-Cookie+ value that removes the sign-in cookie: send it with your
    # error response so a failed sign-in leaves nothing behind.
    class Error < Atlas::Error
      attr_reader :code, :oauth_error, :description, :status
      attr_accessor :clear_cookie

      def initialize(code, message, oauth_error: nil, description: nil, status: nil)
        super(message)
        @code = code
        @oauth_error = oauth_error
        @description = description
        @status = status
      end
    end

    # Who signed in, from a verified ID token.
    Identity = Struct.new(
      :sub, :namespaced_sub, :email, :email_verified, :name, :sid, :auth_time, :return_to,
      :organization, :organizations, :sso, :id_token, :access_token, :refresh_token, :expires_at,
      :claims, :clear_cookie, keyword_init: true
    )

    # The OpenID Connect authorization-code flow with PKCE (S256) for a server-side relying party:
    # build the authorize URL, keep state, nonce and the PKCE verifier in one sealed short-lived
    # httpOnly cookie, and on the callback check +state+, exchange the code, and verify the ID token
    # (algorithm pinned, +iss+, +aud+/+azp+, +exp+/+iat+, +nonce+, +at_hash+).
    #
    # The sealed cookie is the same format the TypeScript relying party writes (HKDF-SHA256 key,
    # AES-256-GCM), so a sign-in may start on one stack and finish on the other.
    class Flow
      FLOW_COOKIE = "atlas_oidc"
      FLOW_MAX_AGE_SECONDS = 600
      ALGORITHMS = JWS::ALGORITHMS
      DISCOVERY_TTL = 3600
      DISCOVERY_RETRY = 60
      SEALED_PREFIX = "s1."
      OWNED_PARAMS = %w[response_type client_id redirect_uri state nonce code_challenge code_challenge_method].freeze

      attr_reader :issuer, :client_id, :redirect_uri, :cookie_name

      # @param http [#call, nil] +call(method, url, headers, body) -> [status, text, headers]+ (the Transport seam).
      # @param now [#call, nil] a clock returning epoch seconds, for tests.
      def initialize(issuer:, client_id:, redirect_uri:, secret:, client_secret: nil, client_auth: nil,
                     cookie_name: FLOW_COOKIE, discovery_url: nil, http: nil, now: nil, clock_tolerance: 60)
        raise ArgumentError, "oidc: issuer is required." if issuer.to_s.strip.empty?
        raise ArgumentError, "oidc: client_id is required." if client_id.to_s.strip.empty?
        raise ArgumentError, "oidc: `secret` (at least 32 characters) seals the sign-in cookie." if secret.to_s.length < 32

        @issuer = issuer.to_s.sub(%r{/+\z}, "")
        @client_id = client_id
        @redirect_uri = redirect_uri
        @redirect = parse_redirect_uri(redirect_uri)
        @secret = secret
        @client_secret = client_secret
        @client_auth = (client_auth || (client_secret ? :client_secret_basic : :none)).to_sym
        @cookie_name = cookie_name
        @discovery_url = discovery_url || "#{@issuer}/.well-known/openid-configuration"
        @http = http || NetHTTPRequester.new
        @now = now
        @clock_tolerance = clock_tolerance
        @jwks = {}
        @discovery = nil
        @mutex = Mutex.new
      end

      # Begin a sign-in.
      # @return [Hash] +{ url:, cookie:, state:, nonce: }+: redirect to +url+ and send +cookie+ as +Set-Cookie+.
      def start(scope: nil, prompt: nil, login_hint: nil, audience_hint: nil, organization: nil, ui_locales: nil,
                max_age: nil, return_to: nil, expected_sub: nil, extra_params: {})
        doc = discover
        if max_age && (!max_age.is_a?(Integer) || max_age.negative?)
          raise ArgumentError, "oidc: `max_age` must be a whole number of seconds, 0 or more."
        end
        raise ArgumentError, "oidc: `return_to` must be a path on this site, starting with a single `/`." if return_to && !self.class.safe_return_to?(return_to)

        state = random_token
        nonce = random_token
        verifier = random_token
        challenge = b64u(OpenSSL::Digest::SHA256.digest(verifier))
        pairs = []
        (extra_params || {}).each do |k, v|
          pairs << [k.to_s, v.to_s] unless v.nil? || OWNED_PARAMS.include?(k.to_s)
        end
        pairs += [["response_type", "code"], ["client_id", @client_id], ["redirect_uri", @redirect_uri],
                  ["scope", normalise_scope(scope)], ["state", state], ["nonce", nonce],
                  ["code_challenge", challenge], ["code_challenge_method", "S256"]]
        pairs << ["prompt", prompt] if prompt
        pairs << ["login_hint", login_hint] if login_hint
        pairs << ["audience_hint", audience_hint] if audience_hint
        pairs << ["organization", organization] if organization
        pairs << ["ui_locales", ui_locales] if ui_locales
        pairs << ["max_age", max_age.to_s] if max_age

        payload = { "s" => state, "n" => nonce, "v" => verifier, "r" => @redirect_uri, "i" => @issuer,
                    "c" => @client_id, "t" => clock }
        payload["m"] = max_age if max_age
        payload["u"] = return_to if return_to
        payload["x"] = expected_sub if expected_sub && !expected_sub.empty?
        url = append_query(doc["authorization_endpoint"], pairs)
        { url: url, cookie: serialize_cookie(seal(payload), FLOW_MAX_AGE_SECONDS), state: state, nonce: nonce }
      end

      # Finish a sign-in.
      # @param query [Hash{String=>String}] the callback's query parameters.
      # @param cookie [String, nil] the request's +Cookie+ header (or just the flow cookie's value).
      # @return [Identity]
      # @raise [Atlas::OIDC::Error]
      def callback(query:, cookie:)
        identity = run_callback(stringify(query), cookie)
        identity.clear_cookie = clear_cookie
        identity
      rescue Error => e
        e.clear_cookie = clear_cookie
        raise
      rescue StandardError => e
        failure = Error.new(:invalid_request, e.message)
        failure.clear_cookie = clear_cookie
        raise failure
      end

      # Verify an ID token on its own (an app doing its own code exchange). Same checks as {#callback}.
      def verify_id_token(id_token, nonce:, access_token: nil)
        check_id_token(id_token, discover, nonce, access_token)
      end

      # The RP-initiated logout URL (+end_session_endpoint+).
      def logout_url(post_logout_redirect_uri: nil, id_token_hint: nil, state: nil)
        endpoint = discover["end_session_endpoint"]
        raise Error.new(:discovery_failed, "The issuer does not advertise an end_session_endpoint.") unless endpoint

        pairs = [["client_id", @client_id]]
        pairs << ["id_token_hint", id_token_hint] if id_token_hint
        pairs << ["post_logout_redirect_uri", post_logout_redirect_uri] if post_logout_redirect_uri
        pairs << ["state", state] if state
        append_query(endpoint, pairs)
      end

      # A +Set-Cookie+ value that removes the sign-in cookie.
      def clear_cookie
        serialize_cookie("", 0)
      end

      # A plain same-site path: one leading +/+, no scheme or authority, no backslash or control characters.
      def self.safe_return_to?(value)
        value.is_a?(String) && value.match?(%r{\A/(?![/\\])[^\\\u0000-\u001f\u007f]*\z})
      end

      # The configured +client_auth+ for the token endpoint (+:client_secret_basic+, +:client_secret_post+ or +:none+).
      attr_reader :client_auth

      # Discovery document, cached; serves the last good copy through an outage.
      def discover
        @mutex.synchronize do
          t = clock
          held = @discovery
          return held[:doc] if held && held[:doc] && t - held[:at] < DISCOVERY_TTL
          raise held[:error] if held && held[:error] && t - held[:at] < DISCOVERY_RETRY

          begin
            @discovery = { doc: fetch_discovery, at: t }
            @discovery[:doc]
          rescue Error => e
            if held && held[:doc]
              @discovery = { doc: held[:doc], at: t }
              held[:doc]
            else
              @discovery = { doc: nil, error: e, at: t }
              raise
            end
          end
        end
      end

      private

      def run_callback(query, cookie)
        raw = read_flow_cookie(cookie)
        raise Error.new(:state_mismatch, "The sign-in flow cookie is missing or expired. Start sign-in again.") unless raw

        flow = open_flow(raw)
        raise Error.new(:state_mismatch, "The sign-in flow cookie could not be read. Start sign-in again.") unless flow

        state = query["state"]
        unless state && secure_compare(state, flow["s"])
          raise Error.new(:state_mismatch, "The `state` returned to the callback does not match this browser's sign-in.")
        end

        now_sec = clock
        if now_sec - flow["t"] > FLOW_MAX_AGE_SECONDS
          raise Error.new(:state_mismatch, "This sign-in took longer than 10 minutes. Start sign-in again.")
        end
        if flow["i"] != @issuer || flow["c"] != @client_id || flow["r"] != @redirect_uri
          raise Error.new(:state_mismatch, "This sign-in was started for a different issuer, client or redirect URI.")
        end

        returned_iss = query["iss"]
        if returned_iss && returned_iss.sub(%r{/+\z}, "") != @issuer
          raise Error.new(:issuer_mismatch, "The callback came from #{returned_iss}, not #{@issuer}.")
        end

        if (oauth_error = query["error"]) && !oauth_error.empty?
          description = query["error_description"]
          raise Error.new(:access_denied,
                          "Sign-in did not complete: #{oauth_error}#{description ? " (#{description})" : ''}.",
                          oauth_error: oauth_error, description: description)
        end

        code = query["code"]
        raise Error.new(:invalid_request, "The callback has no `code` parameter.") if code.nil? || code.empty?

        doc = discover
        tokens = exchange_code(doc, code, flow["v"])
        claims = check_id_token(tokens["id_token"], doc, flow["n"], tokens["access_token"])

        sub = claims["sub"]
        auth_time = claims["auth_time"].is_a?(Numeric) ? claims["auth_time"] : nil
        if flow["m"] && (auth_time.nil? || now_sec - auth_time > flow["m"] + @clock_tolerance)
          raise Error.new(:reauthentication_required,
                          "The sign-in is older than the #{flow['m']} seconds this request allowed (max_age). Ask the user to sign in again.")
        end
        if flow["x"] && !secure_compare(sub.to_s, flow["x"])
          raise Error.new(:subject_mismatch, "A different user signed in than the one asked to confirm it is them.")
        end

        expires_in = Float(tokens["expires_in"], exception: false)
        expires_at = expires_in && expires_in.positive? ? (clock * 1000) + (expires_in * 1000).to_i : claims["exp"].to_i * 1000
        Identity.new(
          sub: sub, namespaced_sub: "#{@issuer}##{sub}",
          email: claims["email"].is_a?(String) ? claims["email"] : nil,
          email_verified: claims["email_verified"] == true,
          name: claims["name"].is_a?(String) ? claims["name"] : nil,
          sid: claims["sid"].is_a?(String) && !claims["sid"].empty? ? claims["sid"] : nil,
          auth_time: auth_time,
          return_to: flow["u"] && self.class.safe_return_to?(flow["u"]) ? flow["u"] : nil,
          organization: Atlas::OIDC.organization_of(claims), organizations: Atlas::OIDC.organizations_of(claims),
          sso: Atlas::OIDC.sso_of(claims),
          id_token: tokens["id_token"], access_token: tokens["access_token"],
          refresh_token: tokens["refresh_token"].is_a?(String) ? tokens["refresh_token"] : nil,
          expires_at: expires_at, claims: claims
        )
      end

      def exchange_code(doc, code, verifier)
        if @client_auth != :none && (@client_secret.nil? || @client_secret.empty?)
          raise Error.new(:token_exchange_failed, "client_auth '#{@client_auth}' needs `client_secret`.")
        end

        form = [["grant_type", "authorization_code"], ["code", code], ["redirect_uri", @redirect_uri], ["code_verifier", verifier]]
        headers = { "content-type" => "application/x-www-form-urlencoded", "accept" => "application/json" }
        if @client_auth == :client_secret_basic
          # RFC 6749 2.3.1: both halves are form-encoded before Basic encoding.
          pair = "#{URI.encode_www_form_component(@client_id)}:#{URI.encode_www_form_component(@client_secret)}"
          headers["authorization"] = "Basic #{Base64.strict_encode64(pair)}"
        else
          form << ["client_id", @client_id]
          form << ["client_secret", @client_secret] if @client_auth == :client_secret_post
        end
        begin
          status, text, = @http.call("POST", doc["token_endpoint"], headers, URI.encode_www_form(form))
        rescue StandardError => e
          raise Error.new(:token_exchange_failed, "The token endpoint could not be reached: #{e.message}.")
        end
        json = parse_json(text)
        unless status.between?(200, 299)
          oauth_error = json.is_a?(Hash) && json["error"].is_a?(String) ? json["error"] : nil
          description = json.is_a?(Hash) && json["error_description"].is_a?(String) ? json["error_description"] : nil
          raise Error.new(:token_exchange_failed,
                          "The token endpoint answered #{status}#{oauth_error ? " #{oauth_error}" : ''}#{description ? ": #{description}" : ''}.",
                          oauth_error: oauth_error, description: description, status: status)
        end
        unless json.is_a?(Hash) && json["id_token"].is_a?(String) && json["access_token"].is_a?(String)
          raise Error.new(:token_exchange_failed, "The token response has no `id_token`. Request the `openid` scope.", status: status)
        end

        json
      end

      def check_id_token(id_token, doc, nonce, access_token)
        invalid = ->(why) { Error.new(:invalid_token, "The ID token was refused: #{why}.") }
        require "jwt"
        header = decode_header(id_token) or raise invalid.call("it is not a JWT")
        # Pinned before any key lookup, so `none` and HS* never get near a key.
        raise invalid.call("its algorithm is #{header['alg']}, not one of #{ALGORITHMS.join(', ')}") unless ALGORITHMS.include?(header["alg"])

        keys = jwks_for(doc["jwks_uri"]).get(header["kid"])
        if keys.nil? || keys["keys"].nil? || keys["keys"].empty?
          raise Error.new(:discovery_failed, "The issuer's signing keys could not be fetched from #{doc['jwks_uri']}.")
        end

        begin
          payload, = JWS.decode(id_token, keys, algorithms: ALGORITHMS, iss: doc["issuer"], aud: @client_id, leeway: @clock_tolerance,
                                                now: -> { clock }, required: %w[sub iat exp])
        rescue JWS::ExpiredError
          raise invalid.call("it has expired")
        rescue JWS::InvalidAudienceError
          raise invalid.call("its audience is not this client")
        rescue JWS::InvalidIssuerError
          raise invalid.call("its issuer is not the configured issuer")
        rescue JWS::VerificationError
          raise invalid.call("its signature does not verify")
        rescue JWS::Error => e
          raise invalid.call(e.message)
        end

        aud = payload["aud"]
        raise invalid.call("it has several audiences and no azp") if aud.is_a?(Array) && aud.length > 1 && !payload.key?("azp")
        raise invalid.call("its azp is #{payload['azp']}, not this client") if payload.key?("azp") && payload["azp"] != @client_id
        raise invalid.call("its nonce does not match this sign-in") unless payload["nonce"].is_a?(String) && secure_compare(payload["nonce"], nonce)
        raise invalid.call("it was issued in the future") if payload["iat"].is_a?(Numeric) && payload["iat"] > clock + @clock_tolerance

        if access_token && payload["at_hash"].is_a?(String)
          digest = OpenSSL::Digest::SHA256.digest(access_token)
          raise invalid.call("its at_hash does not match the access token") unless secure_compare(b64u(digest[0, 16]), payload["at_hash"])
        end
        payload
      end

      def jwks_for(uri)
        @jwks[uri] ||= Atlas::JwksCache.new(
          url: uri, now: @now && -> { @now.call * 1000 },
          fetch_impl: lambda { |url|
            status, text, = @http.call("GET", url, { "accept" => "application/json" }, nil)
            [status, text]
          }
        )
      end

      def fetch_discovery
        fail_with = ->(why) { Error.new(:discovery_failed, "OIDC discovery at #{@discovery_url} failed: #{why}.") }
        begin
          status, text, = @http.call("GET", @discovery_url, { "accept" => "application/json" }, nil)
        rescue StandardError => e
          raise fail_with.call(e.message)
        end
        raise fail_with.call("HTTP #{status}") unless status.between?(200, 299)

        doc = parse_json(text)
        raise fail_with.call("the response is not JSON") unless doc.is_a?(Hash)

        # OIDC Discovery 4.3: the document must be for the issuer we asked about.
        unless doc["issuer"].is_a?(String) && doc["issuer"].sub(%r{/+\z}, "") == @issuer
          raise fail_with.call("its issuer (#{doc['issuer']}) is not #{@issuer}")
        end
        %w[authorization_endpoint token_endpoint jwks_uri].each do |field|
          raise fail_with.call("it has no #{field}") unless doc[field].is_a?(String)
          raise fail_with.call("its #{field} is not an https URL") unless secure_url?(doc[field])
        end
        if doc.key?("end_session_endpoint") && !doc["end_session_endpoint"].is_a?(String)
          raise fail_with.call("its end_session_endpoint is not a string")
        end

        doc.slice("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint")
      end

      # ---- the sealed flow cookie ----

      def flow_key
        @flow_key ||= OpenSSL::KDF.hkdf(@secret, salt: "atlas-oidc-flow-cookie", info: "v1", length: 32, hash: "SHA256")
      end

      def seal(payload)
        cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
        cipher.key = flow_key
        iv = SecureRandom.random_bytes(12)
        cipher.iv = iv
        sealed = cipher.update(JSON.generate(payload)) + cipher.final + cipher.auth_tag(16)
        "#{SEALED_PREFIX}#{b64u(iv)}.#{b64u(sealed)}"
      end

      def open_flow(value)
        # An unsealed cookie is a downgrade: refuse it.
        return nil unless value.start_with?(SEALED_PREFIX)

        iv_part, data_part = value[SEALED_PREFIX.length..].split(".", 2)
        return nil if iv_part.nil? || data_part.nil?

        data = b64u_decode(data_part)
        return nil if data.bytesize < 17

        cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
        cipher.key = flow_key
        cipher.iv = b64u_decode(iv_part)
        cipher.auth_tag = data.byteslice(-16, 16)
        parsed = JSON.parse(cipher.update(data.byteslice(0, data.bytesize - 16)) + cipher.final)
        return nil unless parsed.is_a?(Hash) && %w[s n v r i c].all? { |f| parsed[f].is_a?(String) } && parsed["t"].is_a?(Numeric)
        return nil if parsed.key?("m") && !(parsed["m"].is_a?(Integer) && parsed["m"] >= 0)
        return nil if parsed.key?("u") && !parsed["u"].is_a?(String)
        return nil if parsed.key?("x") && !parsed["x"].is_a?(String)

        parsed
      rescue StandardError
        nil
      end

      def read_flow_cookie(input)
        return nil if input.nil? || input.strip.empty?

        trimmed = input.strip
        return trimmed if trimmed.start_with?(SEALED_PREFIX)

        trimmed.split(";").each do |part|
          name, value = part.split("=", 2)
          next unless value && name.strip == @cookie_name

          v = value.strip
          return v unless v.empty?
        end
        nil
      end

      def serialize_cookie(value, max_age)
        parts = ["#{@cookie_name}=#{value}", "Path=#{@redirect.path.empty? ? '/' : @redirect.path}", "Max-Age=#{max_age}",
                 "HttpOnly", "SameSite=Lax"]
        parts << "Expires=Thu, 01 Jan 1970 00:00:00 GMT" if max_age.zero?
        # Secure except on a plain-http local callback, where the browser would drop it.
        parts << "Secure" if @redirect.scheme == "https"
        parts.join("; ")
      end

      # ---- small helpers ----

      def clock = (@now ? @now.call : Time.now).to_i

      def random_token = b64u(SecureRandom.random_bytes(32))
      def b64u(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
      def b64u_decode(str) = Base64.urlsafe_decode64(str + ("=" * ((4 - (str.length % 4)) % 4)))

      def decode_header(jwt)
        parts = jwt.to_s.split(".")
        return nil unless parts.length == 3 && !parts[0].empty?

        h = JSON.parse(b64u_decode(parts[0]))
        h.is_a?(Hash) ? h : nil
      rescue StandardError
        nil
      end

      def parse_json(text)
        JSON.parse(text.to_s)
      rescue JSON::ParserError
        nil
      end

      # Constant-time comparison that does not leak the position (or the length) of a mismatch.
      def secure_compare(a, b)
        OpenSSL.fixed_length_secure_compare(OpenSSL::Digest::SHA256.digest(a.to_s), OpenSSL::Digest::SHA256.digest(b.to_s))
      end

      def append_query(url, pairs)
        uri = URI.parse(url)
        existing = uri.query ? URI.decode_www_form(uri.query) : []
        uri.query = URI.encode_www_form(existing + pairs)
        uri.to_s
      end

      def normalise_scope(scope)
        parts = (scope || "openid profile email").split(/\s+/).reject(&:empty?)
        parts.unshift("openid") unless parts.include?("openid")
        parts.uniq.join(" ")
      end

      def stringify(query)
        (query || {}).each_with_object({}) { |(k, v), out| out[k.to_s] = (v.is_a?(Array) ? v.first : v).to_s }
      end

      def parse_redirect_uri(value)
        uri = URI.parse(value.to_s)
        loopback = %w[localhost 127.0.0.1 [::1]].include?(uri.host)
        unless uri.scheme == "https" || (uri.scheme == "http" && loopback)
          raise ArgumentError, "oidc: `redirect_uri` must be an https URL (http is accepted only for localhost)."
        end

        uri
      rescue URI::InvalidURIError
        raise ArgumentError, "oidc: `redirect_uri` must be an absolute URL."
      end

      def secure_url?(value)
        uri = URI.parse(value)
        uri.scheme == "https" || (uri.scheme == "http" && %w[localhost 127.0.0.1 [::1]].include?(uri.host))
      rescue URI::InvalidURIError
        false
      end
    end
  end
end
