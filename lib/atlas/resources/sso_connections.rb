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
    end
  end
end
