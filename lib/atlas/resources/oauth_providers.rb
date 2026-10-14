# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/oauth_providers+ — the social sign-in provider catalog + this
    # instance's per-provider credentials and toggles.
    class OAuthProviders < Base
      # The whole catalog, configured or not. Each entry carries +icon_url+,
      # +mode+ and, for wallet providers, +setting_values+.
      #
      # @param params [Hash] optional filters: +provider:+ (one provider key)
      #   and/or +configured:+ (true for only the providers with credentials).
      #
      #   atlas.oauth_providers.list(configured: true)
      def list(params = {})
        request(method: :get, path: "/v1/oauth_providers", query: params)
      end

      def get(provider)
        request(method: :get, path: "/v1/oauth_providers/#{enc(provider)}")
      end

      # Set (or replace) this instance's own credentials for a provider.
      #
      # @param body [Hash] any of:
      #   - +client_id+, +client_secret+ (write-only), +scopes+, +values+,
      #     +custom_redirect_uri+, +native+ — credentials and options;
      #   - +display_name+, +icon_url+ — how Atlas labels the button (these can
      #     be sent alone, without credentials);
      #   - +mode+ — +"native"+ or +"redirect"+ (+""+ clears the override);
      #   - +settings+ — wallet verifier settings for providers with no client
      #     credentials. +siwe+: +domain+, +chain_ids+, +rpc_url+; +siws+:
      #     +domain+, +networks+; +siwf+: +domain+, +chain_ids+,
      #     +optimism_rpc_url+, +id_registry_address+. A +nil+ value clears a
      #     setting. Stored values come back as +setting_values+.
      #
      #   atlas.oauth_providers.upsert("siwe", { settings: { domain: "app.example.com", chain_ids: [1, 10] } })
      #   atlas.oauth_providers.upsert("discord", { display_name: "Community", icon_url: "https://..." })
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
