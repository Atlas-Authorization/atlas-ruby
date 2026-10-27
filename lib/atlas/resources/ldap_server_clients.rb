# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class LdapServerClients < Base
      # List the LDAP interface service accounts with their base DN, bind DN and allowed source
      # networks. Secrets are never returned.
      # Scope: ldap_server:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/ldap_server_clients", query: query)
      end

      # Create a service account for the LDAPS interface: base_dn (dc=/o=/ou= parts, unique across
      # Atlas), bind_cn, allowed_cidrs (empty = nobody may connect), allow_user_bind and size_limit.
      # The secret is returned once as secret.
      # Scope: ldap_server:write. query: dry_run. body requires: name, base_dn, bind_cn.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/ldap_server_clients",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one LDAP interface service account.
      # Scope: ldap_server:read.
      def get(id)
        request(method: :get, path: "/v1/ldap_server_clients/#{enc(id)}")
      end

      # Change the name, allowed networks, user-bind switch, size limit or status (active or
      # disabled).
      # Scope: ldap_server:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/ldap_server_clients/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a service account; its connections can no longer bind.
      # Scope: ldap_server:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/ldap_server_clients/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Issue a new service-account secret (returned once); the old one stops working immediately.
      # Scope: ldap_server:write. query: dry_run.
      def rotate_secret(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/ldap_server_clients/#{enc(id)}/rotate_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
