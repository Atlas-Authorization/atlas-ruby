# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class OrgRoleGrants < Base
      # List cross-organization role grants, filtered by grantor_org_id, grantee_org_id or
      # status=active.
      # Scope: organizations:read. query: grantor_org_id, grantee_org_id, status, limit,
      # starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/org_role_grants", query: query)
      end

      # Let a grantee organization hand out a bounded set of the grantor organization’s roles
      # (role_keys) to its own members. One active grant per pair.
      # Scope: organizations:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/org_role_grants",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Fetch one cross-organization role grant.
      # Scope: organizations:read.
      def get(id)
        request(method: :get, path: "/v1/org_role_grants/#{enc(id)}")
      end

      # Replace the granted role_keys. Delegations of roles no longer granted are removed.
      # Scope: organizations:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/org_role_grants/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Revoke a grant. Every delegation under it stops taking effect immediately.
      # Scope: organizations:write. query: dry_run.
      def revoke(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/org_role_grants/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # List the members holding roles under a grant.
      # Scope: organizations:read. query: limit, starting_after.
      def list_delegations(id, query = nil)
        request(method: :get, path: "/v1/org_role_grants/#{enc(id)}/delegations", query: query)
      end

      # Delegate one granted role_key to a member (user_id) of the grantee organization.
      # Scope: organizations:write. query: dry_run.
      def delegate(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/org_role_grants/#{enc(id)}/delegations",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove a delegation of a granted role.
      # Scope: organizations:write. query: dry_run.
      def undelegate(id, delegation_id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/org_role_grants/#{enc(id)}/delegations/#{enc(delegation_id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # The roles and permissions a user (user_id) holds in a grantor organization (organization_id,
      # optional) through active delegations.
      # Scope: organizations:read. query: user_id (required), organization_id, limit,
      # starting_after.
      def effective(query = nil)
        request(method: :get, path: "/v1/org_role_grants/effective", query: query)
      end
    end
  end
end
