# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/oauth_clients+ — first- and third-party OAuth/OIDC clients, plus their
    # resource-server grants.
    class OAuthClients < Base
      def list
        request(method: :get, path: "/v1/oauth_clients")
      end

      def get(id)
        request(method: :get, path: "/v1/oauth_clients/#{enc(id)}")
      end

      # Create reveals the client secret exactly once.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/oauth_clients", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/oauth_clients/#{enc(id)}", body: body)
      end

      def rotate_secret(id)
        request(method: :post, path: "/v1/oauth_clients/#{enc(id)}/rotate_secret")
      end

      def delete(id)
        request(method: :delete, path: "/v1/oauth_clients/#{enc(id)}")
      end

      # +oauth_clients.grants+ — resource-server grants for a client.
      def grants
        @grants ||= Grants.new(@transport)
      end

      class Grants < Base
        def list(client_id)
          request(method: :get, path: "/v1/oauth_clients/#{enc(client_id)}/grants")
        end

        def create(client_id, body)
          request(method: :post, path: "/v1/oauth_clients/#{enc(client_id)}/grants", body: body)
        end

        def delete(client_id, grant_id)
          request(method: :delete, path: "/v1/oauth_clients/#{enc(client_id)}/grants/#{enc(grant_id)}")
        end
      end
    end
  end
end
