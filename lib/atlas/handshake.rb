# frozen_string_literal: true

require "json"
require "uri"
require "securerandom"
require "digest"
require "base64"

require_relative "error"
require_relative "transport"

module Atlas
  # A fresh session minted by redeeming a cross-property handshake nonce.
  #
  # These are the cookie VALUES a satellite's Rack/Rails handler sets as its own
  # first-party cookies: +jwt+ as +__session+ (script-readable, short-lived) and
  # +refresh_token+ as +__atlas_rt+ (HttpOnly).
  #
  # @!attribute [r] jwt
  #   @return [String] the +__session+ JWT value.
  # @!attribute [r] refresh_token
  #   @return [String] the +__atlas_rt+ refresh value (set HttpOnly).
  # @!attribute [r] session_id
  #   @return [String] the session id ("" when the server omits it).
  # @!attribute [r] expires_in
  #   @return [Integer] seconds until the +__session+ JWT expires.
  HandshakeSession = Struct.new(:jwt, :refresh_token, :session_id, :expires_in, keyword_init: true)

  # Cross-property SSO handshake — the second property's server-side redeem step.
  #
  # When a satellite (a property on a DIFFERENT registrable domain than the main
  # app) has no local session, a middleware bounces the browser through
  # +GET {fapi_origin}/v1/client/handshake+, which — if the user has an Atlas
  # session — redirects back with
  # +?__atlas_hs=ok&__atlas_hu=<user_id>&__atlas_hn=<nonce>+. These helpers read
  # those params and exchange the single-use nonce for a fresh session,
  # server-to-server, so the tokens come back in the response BODY (never a URL).
  #
  # PKCE binding (RFC 7636, S256). The +__atlas_hn+ nonce rides the return URL,
  # which lands in access logs, +Referer+ headers, and browser history — so the
  # nonce alone MUST NOT be a bearer credential. Before bouncing to the handshake
  # we mint a PKCE pair with {create_pkce_pair}: the +challenge+ (a SHA-256 hash)
  # travels on the loggable outbound URL as +code_challenge+, while the +verifier+
  # is stashed server-side in an HttpOnly cookie (+__atlas_hv+, path +/+, ~300s)
  # that never appears in any URL. At redeem we send the +verifier+ back in the
  # request BODY; the Atlas server hashes it and checks it matches the challenge
  # it recorded against the nonce. An attacker who scrapes the nonce out of a log
  # can't redeem it without the verifier, which was never logged. (The Atlas
  # server now REQUIRES +code_verifier+ on redeem — an unbound redeem fails.)
  #
  # Same-registrable-domain SUBDOMAINS don't need this — the handshake sets a
  # parent-domain cookie directly; this is only the cross-domain path.
  #
  # Framework-agnostic usage in a satellite's route handler (Rack/Rails/Sinatra):
  #
  #   params = Atlas::Handshake.read_handshake_params(request.url)
  #   if params
  #     session = Atlas::Handshake.redeem_handshake(
  #       fapi_origin:     "https://id.atlasauth.net",
  #       publishable_key: "pk_live_...",
  #       user_id:         params[:user_id],
  #       nonce:           params[:nonce],
  #       # The verifier we stashed in __atlas_hv when we bounced out (below):
  #       code_verifier:   request.cookies["__atlas_hv"],
  #     )
  #     if session
  #       # Set the satellite's OWN first-party cookies:
  #       response.set_cookie("__session",
  #         value: session.jwt, path: "/", same_site: :lax, secure: true)
  #       response.set_cookie("__atlas_rt",
  #         value: session.refresh_token, path: "/",
  #         httponly: true, same_site: :lax, secure: true)
  #       response.delete_cookie("__atlas_hv") # single-use; done with it.
  #     end
  #     # else: nonce was bad/expired/used — fall through to sign-in.
  #   end
  #
  # A middleware that TRIGGERS the handshake mints a PKCE pair, stashes the
  # verifier, and redirects once to
  # +{fapi_origin}/v1/client/handshake?publishable_key={pk}&redirect_url={current_url}&code_challenge={challenge}+
  # only when there is no local session AND the +__atlas_hs+ query param is absent
  # (its presence means we already came back from the handshake), so it can never
  # loop:
  #
  #   pkce = Atlas::Handshake.create_pkce_pair
  #   response.set_cookie("__atlas_hv",
  #     value: pkce[:verifier], path: "/", max_age: 300,
  #     httponly: true, same_site: :lax, secure: true)
  #   url = "#{fapi_origin}/v1/client/handshake" \
  #     "?publishable_key=#{pk}" \
  #     "&redirect_url=#{CGI.escape(current_url)}" \
  #     "&code_challenge=#{pkce[:challenge]}"
  #   redirect_to url
  module Handshake
    module_function

    # Mint a PKCE pair (RFC 7636, S256) for one handshake round-trip.
    #
    # The handshake nonce travels back to the satellite on a query string, so it
    # is written to access logs, leaked in +Referer+ headers, and kept in browser
    # history. If the nonce alone could be redeemed, anyone who reads one of those
    # logs holds a usable credential. PKCE fixes that by splitting the secret in
    # two: the +challenge+ (an irreversible SHA-256 hash) is what rides the
    # loggable outbound URL as +code_challenge+, and the +verifier+ (the
    # pre-image) is stashed server-side in an HttpOnly cookie (+__atlas_hv+) that
    # never touches a URL. At redeem the verifier is sent in the request BODY and
    # the Atlas server hashes it and checks it against the challenge it bound to
    # the nonce — so a scraped nonce is inert without the verifier, which was
    # never logged.
    #
    # +verifier+ is 32 bytes of {SecureRandom} base64url-encoded without padding
    # (43 chars, well inside RFC 7636's 43–128 range). +challenge+ is the
    # base64url-no-padding SHA-256 digest of the verifier's ASCII bytes (the S256
    # transform). Both use +padding: false+ because RFC 7636 §3 forbids the
    # trailing +=+ and requires the URL-safe alphabet.
    #
    # @return [Hash{Symbol=>String}] +{ verifier:, challenge: }+ — send
    #   +challenge+ on the outbound handshake URL as +code_challenge+, stash
    #   +verifier+ HttpOnly, and pass it back to {redeem_handshake} as
    #   +code_verifier+.
    def create_pkce_pair
      verifier = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
      challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
      { verifier: verifier, challenge: challenge }
    end

    # Redeem a handshake nonce for a fresh session.
    #
    # POSTs to +{fapi_origin}/v1/client/handshake/redeem+ with header
    # +X-Publishable-Key: {publishable_key}+ and JSON body
    # +{ "user_id" => user_id, "nonce" => nonce, "code_verifier" => code_verifier }+.
    #
    # @param fapi_origin [String] origin of the Atlas Frontend API,
    #   e.g. +https://id.atlasauth.net+.
    # @param publishable_key [String] the instance publishable key (+pk_...+).
    # @param user_id [String] the +__atlas_hu+ value from the return URL.
    # @param nonce [String] the single-use +__atlas_hn+ nonce from the return URL.
    # @param code_verifier [String, nil] the PKCE verifier stashed (in the
    #   +__atlas_hv+ HttpOnly cookie) when the handshake was triggered — the
    #   pre-image of the +code_challenge+ that rode the outbound URL. The Atlas
    #   server now REQUIRES this: a redeem without the verifier that matches the
    #   bound challenge fails, and this returns +nil+ like any other bad-nonce.
    # @param http [#call, nil] injectable requester matching the Transport seam —
    #   +call(method, url, headers, body) -> [status_integer, body_string]+.
    #   Defaults to {Atlas::NetHTTPRequester}.
    #
    # @return [Atlas::HandshakeSession, nil] the fresh session, or +nil+ when the
    #   nonce is missing/expired/already used, the verifier doesn't bind, or the
    #   request could not complete. A bad nonce is a normal "signed-out" signal —
    #   this NEVER raises on an auth failure or a transport error, so it can't
    #   take the page down.
    def redeem_handshake(fapi_origin:, publishable_key:, user_id:, nonce:, code_verifier: nil, http: nil)
      requester = http || NetHTTPRequester.new
      url = "#{fapi_origin.sub(%r{/+\z}, '')}/v1/client/handshake/redeem"
      headers = {
        "content-type" => "application/json",
        "accept" => "application/json",
        "x-publishable-key" => publishable_key
      }
      payload = JSON.generate(
        { "user_id" => user_id, "nonce" => nonce, "code_verifier" => code_verifier }
      )

      status, text = requester.call("POST", url, headers, payload)
      return nil unless status.is_a?(Integer) && status.between?(200, 299)

      data = parse_json(text)
      return nil unless data.is_a?(Hash)

      jwt = data["jwt"]
      refresh_token = data["refresh_token"]
      return nil if jwt.nil? || jwt.empty? || refresh_token.nil? || refresh_token.empty?

      HandshakeSession.new(
        jwt: jwt,
        refresh_token: refresh_token,
        session_id: data["session_id"] || "",
        expires_in: (data["expires_in"] || 0).to_i
      )
    rescue StandardError
      # A transport error is indistinguishable, to the user, from a signed-out
      # state — return nil and let the caller fall back to sign-in.
      nil
    end

    # Extract the handshake params from a return URL or query string.
    #
    # @param url_or_query [String] a full URL, a query string, or a bare
    #   +key=value&...+ fragment.
    # @return [Hash{Symbol=>String}, nil] +{ user_id:, nonce: }+ when
    #   +__atlas_hs == "ok"+ and both +__atlas_hu+ and +__atlas_hn+ are present;
    #   +nil+ otherwise.
    def read_handshake_params(url_or_query)
      return nil if url_or_query.nil?

      query = url_or_query.include?("?") ? url_or_query[(url_or_query.index("?") + 1)..] : url_or_query
      query = query.sub(/#.*\z/, "") if query # drop any fragment
      return nil if query.nil? || query.empty?

      params = {}
      URI.decode_www_form(query).each { |key, value| params[key] = value }

      return nil unless params["__atlas_hs"] == "ok"

      user_id = params["__atlas_hu"]
      nonce = params["__atlas_hn"]
      return nil if user_id.nil? || user_id.empty? || nonce.nil? || nonce.empty?

      { user_id: user_id, nonce: nonce }
    rescue StandardError
      nil
    end

    def parse_json(text)
      return nil if text.nil? || text.empty?

      JSON.parse(text)
    rescue JSON::ParserError
      nil
    end
  end

  # Convenience mirrors on the top-level module, matching the standalone auth
  # helpers (+Atlas.has_permission?+, +Atlas.protect+, ...).
  module_function

  # @see Atlas::Handshake.create_pkce_pair
  def create_pkce_pair
    Handshake.create_pkce_pair
  end

  # @see Atlas::Handshake.redeem_handshake
  def redeem_handshake(**kwargs)
    Handshake.redeem_handshake(**kwargs)
  end

  # @see Atlas::Handshake.read_handshake_params
  def read_handshake_params(url_or_query)
    Handshake.read_handshake_params(url_or_query)
  end
end
