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
      def create(params)
        request(method: :post, path: "/v1/sessions", body: params)
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
      #   atlas.sessions.get_token("sess_1", for: "referalli")
      def get_token(id, for:, audience_hint: nil)
        integration = binding.local_variable_get(:for)
        body = audience_hint ? { audience_hint: audience_hint } : Atlas::Transport::OMIT
        request(method: :post, path: "/v1/sessions/#{enc(id)}/integration_tokens/#{enc(integration)}", body: body)
      end
    end
  end
end
