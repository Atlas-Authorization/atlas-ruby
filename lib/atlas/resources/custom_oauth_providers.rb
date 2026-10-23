# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/custom_oauth_providers+ — your own upstream OAuth 2.0 / OpenID Connect
    # login providers, with Atlas as the relying party: endpoints (or just an
    # OIDC issuer), token-endpoint client authentication (incl. private_key_jwt
    # with an Atlas-held key), a declarative +profile_mapping+, upstream
    # +logout+ and +idp_initiated_login+. The provider then signs users in like
    # any built-in one, under its +provider_key+.
    class CustomOAuthProviders < Base
      def list
        request(method: :get, path: "/v1/custom_oauth_providers")
      end

      def get(id)
        request(method: :get, path: "/v1/custom_oauth_providers/#{enc(id)}")
      end

      # +{ provider_key:, display_name:, issuer: | authorization_endpoint: ...,
      # client_id:, client_secret:, token_endpoint_auth_method:, profile_mapping:, ... }+
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/custom_oauth_providers", body: body, idempotency_key: idempotency_key)
      end

      # Patch a provider; a +nil+ value clears a nullable setting.
      def update(id, body)
        request(method: :patch, path: "/v1/custom_oauth_providers/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/custom_oauth_providers/#{enc(id)}")
      end

      # Fetch and validate an issuer's OpenID configuration (for autofill).
      def discover(issuer, discovery_url: nil)
        body = { issuer: issuer }
        body[:discovery_url] = discovery_url if discovery_url
        request(method: :post, path: "/v1/custom_oauth_providers/discover", body: body)
      end

      # Run a mapping against a pasted sample. With +id+ the provider's stored
      # mapping is used unless +body+ carries one.
      def preview_profile_mapping(body, id: nil)
        path = id ? "/v1/custom_oauth_providers/#{enc(id)}/profile_mapping/preview" : "/v1/custom_oauth_providers/profile_mapping/preview"
        request(method: :post, path: path, body: body)
      end

      # The provider's private_key_jwt signing keys.
      def list_signing_keys(id)
        request(method: :get, path: "/v1/custom_oauth_providers/#{enc(id)}/signing_keys")
      end

      # Generate a new active key (+alg+ RS256, PS256 or ES256); the previous one
      # turns +retiring+ (still published).
      def rotate_signing_key(id, alg: nil, idempotency_key: nil)
        request(method: :post, path: "/v1/custom_oauth_providers/#{enc(id)}/signing_keys",
                body: alg ? { alg: alg } : {}, idempotency_key: idempotency_key)
      end

      # Retire a non-active key (it leaves the JWKS).
      def retire_signing_key(id, kid)
        request(method: :post, path: "/v1/custom_oauth_providers/#{enc(id)}/signing_keys/#{enc(kid)}/retire")
      end
    end
  end
end
