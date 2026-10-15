# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/oauth_clients+ — first- and third-party OAuth/OIDC clients, plus their
    # resource-server grants.
    #
    # +skip_logout_confirmation+ (boolean, optional on {#create} and {#update};
    # every client object carries it, default +false+) is for first-party
    # clients only: the API answers 422 +VALIDATION_FAILED+ (param
    # +skip_logout_confirmation+) on a third-party client. When true,
    # RP-initiated logout (+/oauth2/logout+) with this +client_id+ and an exactly
    # registered +post_logout_redirect_uri+ ends the session and redirects
    # straight back with +state+, without the confirmation page.
    #
    #   atlas.oauth_clients.update("oc_123", { skip_logout_confirmation: true })
    class OAuthClients < Base
      def list
        request(method: :get, path: "/v1/oauth_clients")
      end

      def get(id)
        request(method: :get, path: "/v1/oauth_clients/#{enc(id)}")
      end

      # Create reveals the client secret exactly once. The body may include
      # +skip_logout_confirmation+ (first-party clients only).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/oauth_clients", body: body, idempotency_key: idempotency_key)
      end

      # The body may include +skip_logout_confirmation+ (first-party clients only).
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

      # +POST /v1/oauth_clients/import+ — bulk-import OAuth clients for a migration (idempotent per client_id).
      def import(clients, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/oauth_clients/import",
          body: { clients: clients },
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
