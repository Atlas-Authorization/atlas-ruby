# frozen_string_literal: true

require_relative "risk_based_mfa"

module Atlas
  module Resources
    class RiskBasedMfa
      # Store (write-only, encrypted) the API key of your IP-reputation provider (ipqs, spur or
      # minfraud; minFraud uses "<account id>:<license key>"). Then set +reputation.provider+ on
      # PATCH /v1/risk_based_mfa. Lookups are cached and fail open: a provider outage never blocks a
      # sign-in.
      # Scope: risk_based_mfa:write. query: dry_run.
      def set_reputation_secret(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/risk_based_mfa/reputation_secret",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove a stored IP-reputation provider key (default: the configured provider). IP lookups
      # for that provider stop; sign-in is unaffected.
      # Scope: risk_based_mfa:write. query: dry_run, provider.
      def remove_reputation_secret(query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/risk_based_mfa/reputation_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
