# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/resource_servers+ — API audiences and the scopes they define.
    class ResourceServers < Base
      def list
        request(method: :get, path: "/v1/resource_servers")
      end

      def get(id)
        request(method: :get, path: "/v1/resource_servers/#{enc(id)}")
      end

      def create(body)
        request(method: :post, path: "/v1/resource_servers", body: body)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/resource_servers/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/resource_servers/#{enc(id)}")
      end
    end
  end
end
