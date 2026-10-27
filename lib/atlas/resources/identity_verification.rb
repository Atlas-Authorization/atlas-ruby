# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class IdentityVerification < Base
      # Whether identity verification is on, and which connector does the checking.
      # Scope: identity_verification:read.
      def settings
        request(method: :get, path: "/v1/identity_verification/settings")
      end

      # Turn identity verification on or off and choose the connector (a Persona, Onfido, Veriff or
      # Stripe Identity service connector; its credentials stay in the vault). +as_challenge+ offers
      # a verified identity as the custom second step of sign-in (the custom challenge factor must
      # be enabled).
      # Scope: identity_verification:write. query: dry_run.
      def update_settings(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/identity_verification/settings",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List checks by status (default +needs_review+, the review queue), newest first.
      # Scope: identity_verification:read. query: status, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/identity_verifications", query: query)
      end

      # Read one check. A pending check is refreshed from the verification service first.
      # Scope: identity_verification:read.
      def get(id)
        request(method: :get, path: "/v1/identity_verifications/#{enc(id)}")
      end

      # Decide a check that is waiting for review (or override a pending one) as +approved+ or
      # +declined+. The outcome is written to the user as +verification.identity+. 409 when the
      # check is already approved or declined.
      # Scope: identity_verification:write. query: dry_run.
      def decide(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/identity_verifications/#{enc(id)}/decide",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # A user's identity checks, newest first.
      # Scope: identity_verification:read. query: limit, starting_after.
      def for_user(id, query = nil)
        request(method: :get, path: "/v1/users/#{enc(id)}/identity_verifications", query: query)
      end

      # Start an identity check for a user and get the verification service's hosted page (+url+) to
      # send them to. A check started in the last 30 minutes and still pending is returned instead
      # of a new one; at most 5 checks per user per hour. 409 when identity verification is not
      # turned on.
      # Scope: identity_verification:write. query: dry_run.
      def start(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/identity_verifications",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
