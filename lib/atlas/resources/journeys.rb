# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Journeys < Base
      # The sign-in journeys.
      # Scope: actions:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/flows", query: query)
      end

      # Create a sign-in journey (version 1, active unless activate is false). Steps run top to
      # bottom once a sign-in has passed its factors: refusals (deny, require_method, require_mfa),
      # required actions the user must finish first, Action calls that may refuse, session claims
      # and the redirect after sign-in. Action steps must name workflow_step Actions. → 201.
      # Scope: actions:write. query: dry_run. body requires: name, definition.
      def create(body, query = nil, idempotency_key: nil)
        request(method: :post, path: "/v1/flows", query: query, body: body, idempotency_key: idempotency_key)
      end

      # One journey with its active definition (else the latest).
      # Scope: actions:read.
      def get(id)
        request(method: :get, path: "/v1/flows/#{enc(id)}")
      end

      # Change a journey. A definition becomes the next version (immutable), active unless activate
      # is false.
      # Scope: actions:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/flows/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a journey and its versions.
      # Scope: actions:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(method: :delete, path: "/v1/flows/#{enc(id)}", query: query, idempotency_key: idempotency_key)
      end

      # Every version of a journey, newest first.
      # Scope: actions:read. query: limit, starting_after.
      def versions(id, query = nil)
        request(method: :get, path: "/v1/flows/#{enc(id)}/versions", query: query)
      end

      # Make a version the active one (roll forward or back).
      # Scope: actions:write. query: dry_run. body requires: version.
      def activate(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/flows/#{enc(id)}/activate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # What-if: run a version (default the active one) for a user and a described sign-in (method,
      # mfa_verified, ip, application_id) without changing anything. Returns the outcome (allowed,
      # held or refused), the effects and a per-step trace.
      # Scope: actions:read. query: dry_run. body requires: user_id.
      def simulate(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/flows/#{enc(id)}/simulate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
