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

      # Mint a new secret, revealed exactly once. The previous secret keeps
      # working for +overlap_seconds+ (default 86400 = 24 hours, at most 604800
      # = 7 days; +0+ revokes it now, e.g. after a leak). The response carries
      # +client_secret+, +overlap_seconds+ and +previous_secret_expires_at+
      # (epoch ms, or +nil+ when the old secret already stopped working); every
      # client object carries +previous_secret_expires_at+ too.
      #
      #   atlas.oauth_clients.rotate_secret("oc_123", { overlap_seconds: 3600 })
      def rotate_secret(id, body = Atlas::Transport::OMIT, idempotency_key: nil)
        request(method: :post, path: "/v1/oauth_clients/#{enc(id)}/rotate_secret", body: body, idempotency_key: idempotency_key)
      end

      def delete(id)
        request(method: :delete, path: "/v1/oauth_clients/#{enc(id)}")
      end

      # +GET /v1/oauth_clients/:id/backchannel_deliveries+ — the client's
      # back-channel logout delivery log, newest first (+limit:+,
      # +starting_after:+). Each delivery has +status+, +http_status+,
      # +latency_ms+, +error+, +location+ (a 3xx is never followed) and +test+.
      def list_backchannel_deliveries(id, params = {})
        request(method: :get, path: "/v1/oauth_clients/#{enc(id)}/backchannel_deliveries", query: params)
      end

      # +POST /v1/oauth_clients/:id/backchannel_logout/test+ — send a test
      # back-channel logout now (+ok+, +status+, +latency_ms+, +error+,
      # +location+, +blocked_reason+, +body_excerpt+).
      def test_backchannel_logout(id)
        request(method: :post, path: "/v1/oauth_clients/#{enc(id)}/backchannel_logout/test")
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
