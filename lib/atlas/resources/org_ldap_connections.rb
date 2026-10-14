# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/org_ldap_connections+ — organization-owned LDAP / Active Directory connections.
    class OrgLdapConnections < Base
      # +GET /v1/org_ldap_connections+ — organization-owned LDAP / Active Directory connections (never the bind password). Filter with organization_id:.
      def list(params = {})
        request(method: :get, path: "/v1/org_ldap_connections", query: params)
      end

      # +POST /v1/org_ldap_connections+ — create an organization's LDAP connection (one per organization).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/org_ldap_connections", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/org_ldap_connections/:id+ — one LDAP connection.
      def get(id)
        request(method: :get, path: "/v1/org_ldap_connections/#{enc(id)}")
      end

      # +PATCH /v1/org_ldap_connections/:id+ — update an LDAP connection.
      def update(id, body, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/org_ldap_connections/#{enc(id)}",
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # +DELETE /v1/org_ldap_connections/:id+ — delete an LDAP connection.
      def delete(id, idempotency_key: nil)
        request(method: :delete, path: "/v1/org_ldap_connections/#{enc(id)}", idempotency_key: idempotency_key)
      end

      # +POST /v1/org_ldap_connections/:id/test+ — test an LDAP connection with a service-account bind.
      def test(id, body = {})
        request(method: :post, path: "/v1/org_ldap_connections/#{enc(id)}/test", body: body)
      end
    end
  end
end
