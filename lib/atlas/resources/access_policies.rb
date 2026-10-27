# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AccessPolicies < Base
      # List conditional-access policies, in evaluation order.
      # Scope: access_policies:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/access_policies", query: query)
      end

      # Create a conditional-access policy. +conditions+ (applications, userIds, groups, orgs,
      # roles, networkZones {include, exclude}, countries, riskLevels, deviceTrust, authMethods,
      # timeWindow) are ANDed; an empty condition matches anything. +grants+ are allow, block,
      # require_mfa, require_acr, require_policy_acceptance or require_action. +stages+ limits it to
      # sign_in, authorize and/or token (default all). A matching block wins; step-up grants are
      # unioned.
      # Scope: access_policies:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/access_policies",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # What-if: describe a request (stage, ip, application, orgs, roles, country, risk level,
      # device trust, auth methods, whether MFA was verified) and see the decision, the policies
      # that matched and the unmet step-up requirements. Pass +policy_id+ to test one policy even if
      # it is disabled.
      # Scope: access_policies:read. query: dry_run.
      def simulate(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/access_policies/simulate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one access policy.
      # Scope: access_policies:read.
      def get(id)
        request(method: :get, path: "/v1/access_policies/#{enc(id)}")
      end

      # Update an access policy. Sent fields replace the stored value.
      # Scope: access_policies:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/access_policies/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete an access policy.
      # Scope: access_policies:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/access_policies/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
