# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class OauthClientProfiles < Base
      # List the OAuth client policy profiles: the built-ins (fapi2_security, fapi2_message_signing,
      # pkce_required, par_required, dpop_required) and your custom ones.
      # Scope: oauth_clients:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/oauth_client_profiles", query: query)
      end

      # Create or replace a custom client policy profile (rules: PKCE, PAR, sender constraint,
      # signed request object, allowed auth methods and signing algorithms, https-only redirects,
      # allowed claims). Built-in names are reserved.
      # Scope: oauth_clients:write. query: dry_run.
      def set(name, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/oauth_client_profiles/#{enc(name)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a custom client policy profile. 409 while any client is assigned it.
      # Scope: oauth_clients:write. query: dry_run.
      def delete(name, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/oauth_client_profiles/#{enc(name)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
