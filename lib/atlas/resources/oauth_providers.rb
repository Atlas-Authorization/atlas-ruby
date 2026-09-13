# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/oauth_providers+ — the social sign-in provider catalog + this
    # instance's per-provider credentials and toggles.
    class OAuthProviders < Base
      # The whole catalog, configured or not.
      def list
        request(method: :get, path: "/v1/oauth_providers")
      end

      def get(provider)
        request(method: :get, path: "/v1/oauth_providers/#{enc(provider)}")
      end

      # Set (or replace) this instance's own credentials for a provider.
      def upsert(provider, body, idempotency_key: nil)
        request(method: :put, path: "/v1/oauth_providers/#{enc(provider)}", body: body, idempotency_key: idempotency_key)
      end

      def delete(provider)
        request(method: :delete, path: "/v1/oauth_providers/#{enc(provider)}")
      end

      # Turn a configured provider on or off.
      def set_enabled(provider, enabled)
        request(method: :post, path: "/v1/oauth_providers/#{enc(provider)}/enabled", body: { enabled: enabled })
      end

      # §6.5 which screens this provider serves. At least one must be true.
      def set_scope(provider, body)
        request(method: :post, path: "/v1/oauth_providers/#{enc(provider)}/scope", body: body)
      end

      # Verify the stored credentials against the provider's token endpoint.
      def test(provider)
        request(method: :post, path: "/v1/oauth_providers/#{enc(provider)}/test")
      end
    end
  end
end
