# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/migrations/better_auth/*+ — the Better Auth session bridge: during a
    # migration window a returning user's Better Auth session is exchanged, once,
    # for an Atlas session, so nobody is signed out by the switch. See
    # {Atlas::BetterAuth.exchange} and {Atlas::BetterAuth::RackMiddleware}.
    class BetterAuthBridge < Base
      # +GET /v1/migrations/better_auth/bridge+ — settings and exchange counts
      # (+live_fallback.has_secret+, never the secret).
      def get
        request(method: :get, path: "/v1/migrations/better_auth/bridge")
      end

      # +PUT /v1/migrations/better_auth/bridge+ — create or update the settings
      # (+enabled+, +ends_at+, +cookie_prefix+, +live_fallback: { enabled, base_url, secret }+),
      # merged onto the stored ones. The secret is write-only: omit to keep, +nil+ to clear.
      def update(body, idempotency_key: nil)
        request(method: :put, path: "/v1/migrations/better_auth/bridge", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/migrations/better_auth/bridge+ — the bridge is off and the stored secret deleted.
      def delete(idempotency_key: nil)
        request(method: :delete, path: "/v1/migrations/better_auth/bridge", idempotency_key: idempotency_key)
      end

      # +POST /v1/migrations/better_auth/exchange+ — exchange a Better Auth session
      # (the raw cookie value or the bare token) for an Atlas session, once.
      # Returns +session_tokens+, or a +sign_in_attempt+ when a second factor is
      # owed. +client_ip+ / +user_agent+ are the END USER's, forwarded so Atlas's
      # guards, risk and geo checks and the device record see the user. Raises
      # {Atlas::APIError} on refusal; {Atlas::BetterAuth.exchange} classifies it.
      def exchange(token, client_ip: nil, user_agent: nil, remember: nil)
        body = { token: token }
        body[:remember] = false if remember == false
        headers = {}
        headers["x-atlas-client-ip"] = client_ip if client_ip && !client_ip.to_s.empty?
        headers["x-atlas-client-user-agent"] = user_agent if user_agent && !user_agent.to_s.empty?
        request(method: :post, path: "/v1/migrations/better_auth/exchange", body: body, headers: headers)
      end
    end
  end
end
