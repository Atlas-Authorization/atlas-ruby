# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sso_connections+ — enterprise SSO connections (OIDC, SAML, Discourse).
    class SsoConnections < Base
      def list
        request(method: :get, path: "/v1/sso_connections")
      end

      def get(id)
        request(method: :get, path: "/v1/sso_connections/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sso_connections", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/sso_connections/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/sso_connections/#{enc(id)}")
      end

      # SP SAML metadata for a connection (JSON envelope carrying the XML).
      def saml_metadata(id)
        request(method: :get, path: "/v1/sso_connections/#{enc(id)}/saml_metadata")
      end

      # OIDC: run the connection's profile mapping (or the body's) against a
      # pasted sample: +{ profile_mapping:, userinfo:, id_token_claims:, id_token: }+.
      def preview_profile_mapping(id, body)
        request(method: :post, path: "/v1/sso_connections/#{enc(id)}/profile_mapping/preview", body: body)
      end

      # OIDC: the connection's private_key_jwt signing keys.
      def list_signing_keys(id)
        request(method: :get, path: "/v1/sso_connections/#{enc(id)}/signing_keys")
      end

      # Generate a new active key (+alg+ RS256, PS256 or ES256); the previous one
      # turns +retiring+ (still published).
      def rotate_signing_key(id, alg: nil)
        request(method: :post, path: "/v1/sso_connections/#{enc(id)}/signing_keys", body: alg ? { alg: alg } : {})
      end

      # Retire a non-active key (it leaves the JWKS).
      def retire_signing_key(id, kid)
        request(method: :post, path: "/v1/sso_connections/#{enc(id)}/signing_keys/#{enc(kid)}/retire")
      end

      # The SAML connection's SP encryption certificate(s).
      def get_saml_encryption_key(id)
        request(method: :get, path: "/v1/sso_connections/#{enc(id)}/saml_encryption_key")
      end

      # Generate the SP encryption key pair, or ROTATE it when one exists: the
      # current pair becomes the previous one (still advertised and accepted
      # until {#retire_previous_saml_encryption_key}).
      def create_saml_encryption_key(id, idempotency_key: nil)
        request(method: :post, path: "/v1/sso_connections/#{enc(id)}/saml_encryption_key",
                idempotency_key: idempotency_key)
      end

      # Finish a rotation: stop accepting the previous encryption key.
      def retire_previous_saml_encryption_key(id)
        request(method: :delete, path: "/v1/sso_connections/#{enc(id)}/saml_encryption_key/previous")
      end

      # Turn assertion encryption off (refused while encrypted assertions are
      # required).
      def delete_saml_encryption_key(id)
        request(method: :delete, path: "/v1/sso_connections/#{enc(id)}/saml_encryption_key")
      end
    end
  end
end
