# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/radius_clients+ — RADIUS NAS clients allowed to authenticate users.
    class RadiusClients < Base
      def list
        request(method: :get, path: "/v1/radius_clients")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/radius_clients", body: body, idempotency_key: idempotency_key)
      end

      def get(id)
        request(method: :get, path: "/v1/radius_clients/#{enc(id)}")
      end

      def update(id, body)
        request(method: :patch, path: "/v1/radius_clients/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/radius_clients/#{enc(id)}")
      end
    end
  end
end
