# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class ManagedGrants < Base
      # List OpenID Grant Management grants: what each OAuth client holds for each user under a
      # +grant_id+, newest first. Filter by +user_id+, +client_id+ (the public client id) and
      # +status+.
      # Scope: grants:read. query: user_id, client_id, status, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/grant_management/grants", query: query)
      end

      # Read one grant: its scopes, resource, authorization_details, status and revision.
      # Scope: grants:read.
      def get(id)
        request(method: :get, path: "/v1/grant_management/grants/#{enc(id)}")
      end

      # Narrow a grant: send the +scopes+ and/or +authorization_details+ it should keep. Anything it
      # does not already hold is a 400 (only the user widens a grant, by authorizing again with
      # +grant_management_action=merge+). Refresh tokens under the grant are clamped to the narrower
      # scope; a revoked grant is a 404.
      # Scope: grants:write. query: dry_run.
      def narrow(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/grant_management/grants/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Revoke a grant and everything issued under it: refresh tokens stop refreshing and access
      # tokens that carry the +grant_id+ stop validating at once. +tokens_ended+ counts the refresh
      # grants that ended with it. Revoking an already-revoked grant answers 200 with +tokens_ended:
      # 0+.
      # Scope: grants:write. query: dry_run.
      def revoke(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/grant_management/grants/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
