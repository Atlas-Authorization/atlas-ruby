# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/connectors+ — community connector profiles you publish to the directory.
    class Connectors < Base
      # +GET /v1/connectors+ — your own community connector profiles (draft and published).
      def list
        request(method: :get, path: "/v1/connectors")
      end

      # +POST /v1/connectors+ — create a community connector profile.
      def create(body)
        request(method: :post, path: "/v1/connectors", body: body)
      end

      # +GET /v1/connectors/:id+ — one of your connector profiles.
      def get(id)
        request(method: :get, path: "/v1/connectors/#{enc(id)}")
      end

      # +PATCH /v1/connectors/:id+ — edit a connector profile.
      def update(id, body)
        request(method: :patch, path: "/v1/connectors/#{enc(id)}", body: body)
      end

      # +DELETE /v1/connectors/:id+ — delete a connector profile with its installs and reviews.
      def delete(id)
        request(method: :delete, path: "/v1/connectors/#{enc(id)}")
      end

      # +POST /v1/connectors/:id/publish+ — publish a connector to the public directory.
      def publish(id)
        request(method: :post, path: "/v1/connectors/#{enc(id)}/publish")
      end

      # +POST /v1/connectors/:id/unlist+ — remove a published connector from the directory without deleting it.
      def unlist(id)
        request(method: :post, path: "/v1/connectors/#{enc(id)}/unlist")
      end

      # +POST /v1/connectors/:id/shared_credentials+ — set, rotate or revoke (revoke: true) the shared OAuth credentials.
      def set_shared_credentials(id, body)
        request(method: :post, path: "/v1/connectors/#{enc(id)}/shared_credentials", body: body)
      end

      # +POST /v1/connectors/:slug/install+ — enable a published connector on your instance.
      def install(slug, body = {})
        request(method: :post, path: "/v1/connectors/#{enc(slug)}/install", body: body)
      end

      # +POST /v1/connectors/:slug/reviews+ — rate a connector you installed (rating 1-5, optional body).
      def review(slug, body)
        request(method: :post, path: "/v1/connectors/#{enc(slug)}/reviews", body: body)
      end
    end
  end
end
