# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AuthzDecisions < Base
      # Query the authorization decision log, newest first: ABAC, AuthZEN, FGA-check and
      # access-policy decisions with their redacted input, result, the policy revision in force and
      # latency. Only decisions that passed sampling are stored.
      # Scope: authz_decisions:read. query: source, decision, principal, action, resource,
      # policy_revision, since, until, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/authz_decisions", query: query)
      end

      # Decision counts per engine and outcome over a window (the last 24 hours by default), with a
      # sampling-corrected estimate of the true volume and latency percentiles of the recorded
      # decisions.
      # Scope: authz_decisions:read. query: since, until.
      def stats(query = nil)
        request(method: :get, path: "/v1/authz_decisions/stats", query: query)
      end

      # Read one logged decision.
      # Scope: authz_decisions:read.
      def get(id)
        request(method: :get, path: "/v1/authz_decisions/#{enc(id)}")
      end

      def settings
        @settings ||= Settings.new(@transport)
      end

      class Settings < Base
        # How authorization decisions are captured: on or off, sampling per outcome, how much of
        # each request is kept, redaction paths, event shipping and retention.
        # Scope: authz_decisions:read.
        def get
          request(method: :get, path: "/v1/authz_decision_settings")
        end

        # Change how decisions are captured. Fields you omit keep their value. Capture is off by
        # default; +input_mode+ defaults to +ids+ (identifiers only) so nothing personal is stored
        # until you ask for it. With +ship_to_events+ each recorded decision is also an
        # +authz.decision+ event for your log streams and webhooks.
        # Scope: authz_decisions:write. query: dry_run.
        def update(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/authz_decision_settings",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
