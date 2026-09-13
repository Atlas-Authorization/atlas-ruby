# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/jwt_templates+ — custom JWT claim templates, keyed by name.
    class JwtTemplates < Base
      def list
        request(method: :get, path: "/v1/jwt_templates")
      end

      # Fetched by template name.
      def get(name)
        request(method: :get, path: "/v1/jwt_templates/#{enc(name)}")
      end

      def create(body)
        request(method: :post, path: "/v1/jwt_templates", body: body)
      end

      # Only the claims are updatable; the name is the key.
      def update(name, body)
        request(method: :patch, path: "/v1/jwt_templates/#{enc(name)}", body: body)
      end

      def delete(name)
        request(method: :delete, path: "/v1/jwt_templates/#{enc(name)}")
      end
    end
  end
end
