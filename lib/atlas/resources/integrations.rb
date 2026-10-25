# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance/integrations+ — suite integrations (a product connected to this
    # instance: principal claim, events URL, back-channel logout, health) and the
    # server-side minting of integration tokens.
    #
    # View fields: +id+, +product+, +preset+, +name+, +role+, +connected+,
    # +principal_claim+, +ext_claim+, +ttl_seconds+, +events_url+ (+_default+),
    # +events+, +backchannel_logout_url+ (+_default+), +verify_error_report_url+,
    # +cmp+, +atlas_id_users+, +atlas_id_issuer+, +external_ref+, +enabled_at+,
    # +updated_at+, +health+, +dry_run+.
    class Integrations < Base
      def list
        request(method: :get, path: "/v1/instance/integrations")
      end

      def get(id)
        request(method: :get, path: "/v1/instance/integrations/#{enc(id)}")
      end

      # Connect or replace an integration. +dry_run: true+ validates and writes nothing.
      # +per_call_audience+ (+{ param:, template:, allowed: [], any_matching: }+) sets which
      # per-call audiences a token mint may ask for; +nil+ allows the configured audience only.
      def set(id, body, dry_run: false, idempotency_key: nil)
        request(method: :put, path: "/v1/instance/integrations/#{enc(id)}", body: body,
                query: Atlas::Resources.dry_run_query(dry_run), idempotency_key: idempotency_key)
      end

      def delete(id, dry_run: false)
        request(method: :delete, path: "/v1/instance/integrations/#{enc(id)}", query: Atlas::Resources.dry_run_query(dry_run))
      end

      # Delivery log for the integration's events. +params+ may carry +trace+.
      def deliveries(id, params = {})
        request(method: :get, path: "/v1/instance/integrations/#{enc(id)}/deliveries", query: params.empty? ? nil : params)
      end

      # Mint (and reveal once) the integration's events secret.
      def events_secret(id)
        request(method: :post, path: "/v1/instance/integrations/#{enc(id)}/events_secret")
      end

      def atlas_id_tokens(id, body = Atlas::Transport::OMIT)
        request(method: :post, path: "/v1/instance/integrations/#{enc(id)}/atlas_id_tokens", body: body)
      end

      # +POST /v1/sessions/:session_id/integration_tokens/:integration+ — mint a
      # token for another product of the suite from a session, server side.
      # The server-side peer of +getToken({ for: integration })+.
      def mint_token(session_id, integration, body = Atlas::Transport::OMIT, idempotency_key: nil, query: nil)
        request(method: :post, path: "/v1/sessions/#{enc(session_id)}/integration_tokens/#{enc(integration)}",
                body: body, idempotency_key: idempotency_key, query: query)
      end

      # +getToken({ for: })+ — mint an integration token for a session; the
      # optional +audience_hint+ is sent as the ticket-exchange body. A per-call audience
      # (+audience+, +cbid+ or +audience_params+, the integration's own parameter) follows the
      # integration's +per_call_audience+ (+param+, +template+, +allowed+, +any_matching+;
      # +nil+ turns it off); one it does not permit is refused with 403.
      #
      #   atlas.integrations.get_token("sess_1", for: "referalli")
      #   atlas.integrations.get_token("sess_1", for: "acme", audience: "acme:t1")
      def get_token(session_id, for:, audience_hint: nil, audience: nil, cbid: nil, audience_params: nil)
        integration = binding.local_variable_get(:for)
        body = audience_hint ? { audience_hint: audience_hint } : Atlas::Transport::OMIT
        mint_token(session_id, integration, body,
                   query: Atlas::Resources.audience_query(audience: audience, cbid: cbid, params: audience_params))
      end

      # +POST /v1/integrations/verify_errors+ — report a token-verification failure from a receiver.
      def report_verify_error(body)
        request(method: :post, path: "/v1/integrations/verify_errors", body: body)
      end

      # +GET /v1/integrations/:id/card+ — the integration's card (state + actions).
      def card(id)
        request(method: :get, path: "/v1/integrations/#{enc(id)}/card")
      end

      def card_revoke_sessions(id, body = Atlas::Transport::OMIT)
        request(method: :post, path: "/v1/integrations/#{enc(id)}/card/actions/revoke_sessions", body: body)
      end

      # +GET /v1/public/instances/:id+ — public facts about an instance (no key needed).
      def public_instance(id)
        request(method: :get, path: "/v1/public/instances/#{enc(id)}")
      end
    end
  end
end
