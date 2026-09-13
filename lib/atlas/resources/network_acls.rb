# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/network_acls+ — per-instance IP allow/deny rules, priority-ordered.
    class NetworkAcls < Base
      def list
        request(method: :get, path: "/v1/network_acls")
      end

      def get(id)
        request(method: :get, path: "/v1/network_acls/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/network_acls", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/network_acls/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/network_acls/#{enc(id)}")
      end
    end
  end
end
