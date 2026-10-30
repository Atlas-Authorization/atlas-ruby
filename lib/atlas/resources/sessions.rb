# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sessions+ — mint, list, inspect, and revoke sessions. Every session
    # object carries +idle_expires_at+ (epoch ms the session ends from
    # inactivity; same value as +abandon_at+).
    class Sessions < Base
      # +POST /v1/sessions+ — mint a session for a user without the sign-in flow.
      # Returns the bearer jwt + refresh token in-body. Refused for a banned user.
      # With +mode: "browser_ticket"+ (+redirect_url+, +expires_in_seconds+) it
      # returns a browser ticket instead: see {#create_browser_ticket}.
      def create(params)
        request(method: :post, path: "/v1/sessions", body: params)
      end

      # +POST /v1/sessions+ with +mode: "browser_ticket"+ — a one-time ticket that
      # signs a BROWSER in as the user (support handoffs, E2E). No session is minted
      # here. +redirect_url+ (an allowed origin) makes the response carry a ready
      # +url+; +expires_in_seconds+ is 1 to 300 (default 60). Returns +{ "object" =>
      # "browser_ticket", "id", "user_id", "ticket", "url", "redirect_url",
      # "expires_in", "expires_at" (ISO 8601) }+. Successor of +sign_in_tokens.create+.
      def create_browser_ticket(user_id, redirect_url: nil, expires_in_seconds: nil)
        body = { user_id: user_id, mode: "browser_ticket" }
        body[:redirect_url] = redirect_url unless redirect_url.nil?
        body[:expires_in_seconds] = expires_in_seconds unless expires_in_seconds.nil?
        request(method: :post, path: "/v1/sessions", body: body)
      end

      # +GET /v1/sessions?user_id=+ — requires a +user_id+.
      def list(params)
        request(method: :get, path: "/v1/sessions", query: params)
      end

      def get(id)
        request(method: :get, path: "/v1/sessions/#{enc(id)}")
      end

      def revoke(id)
        request(method: :post, path: "/v1/sessions/#{enc(id)}/revoke")
      end

      # +POST /v1/sessions/:id/touch+ — keep a session alive from your backend:
      # slides its inactivity window as if the user had just loaded a page, never
      # past the absolute expiry. Returns the session plus +extended+ (false when a
      # touch within the last minute already moved it, so calling it on every
      # request is safe). An ended session raises a 409 (+SESSION_REVOKED+,
      # +SESSION_IDLE_EXPIRED+ or +SESSION_EXPIRED+).
      def touch(id)
        request(method: :post, path: "/v1/sessions/#{enc(id)}/touch")
      end

      # +POST /v1/sessions/:id/tokens/:template+ — mint a token from a named JWT template for a session.
      def create_token(id, template)
        request(method: :post, path: "/v1/sessions/#{enc(id)}/tokens/#{enc(template)}")
      end

      # +PUT /v1/sessions/:id/custom_data+ — replace the session's custom data
      # (+nil+ clears it). At most 2 KB; only an active session can be changed.
      # Not for secrets: the signed-in user can read it. Sends the
      # +session.updated+ webhook.
      def set_custom_data(id, custom_data)
        request(method: :put, path: "/v1/sessions/#{enc(id)}/custom_data", body: { custom_data: custom_data })
      end

      # +PATCH /v1/sessions/:id/custom_data+ — merge keys; a key set to +nil+ is
      # removed.
      def update_custom_data(id, patch)
        request(method: :patch, path: "/v1/sessions/#{enc(id)}/custom_data", body: { custom_data: patch })
      end

      # +getToken({ for: })+ — mint a token for another product of the suite from
      # this session, server side (+POST /v1/sessions/:id/integration_tokens/:integration+).
      # +audience_hint+ is optional.
      #
      # A per-call audience picks the token's +aud+ for this one mint, when the
      # integration's +per_call_audience+ permits it (otherwise 403): +audience+ is the
      # whole audience, +cbid+ the site id of an integration whose parameter is +cbid+,
      # and +audience_params+ any integration's own parameter (+{ tenant: "t1" }+).
      #
      #   atlas.sessions.get_token("sess_1", for: "referalli")
      #   atlas.sessions.get_token("sess_1", for: "acme", audience_params: { tenant: "t1" })
      def get_token(id, for:, audience_hint: nil, audience: nil, cbid: nil, audience_params: nil)
        integration = binding.local_variable_get(:for)
        body = audience_hint ? { audience_hint: audience_hint } : Atlas::Transport::OMIT
        request(method: :post, path: "/v1/sessions/#{enc(id)}/integration_tokens/#{enc(integration)}", body: body,
                query: Atlas::Resources.audience_query(audience: audience, cbid: cbid, params: audience_params))
      end
    end
  end
end
