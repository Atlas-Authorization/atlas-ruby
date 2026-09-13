# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/domains+ — custom FAPI/accounts domains and their DNS verification.
    class Domains < Base
      def list
        request(method: :get, path: "/v1/domains")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/domains", body: body, idempotency_key: idempotency_key)
      end

      def verify(id)
        request(method: :post, path: "/v1/domains/#{enc(id)}/verify")
      end

      def delete(id)
        request(method: :delete, path: "/v1/domains/#{enc(id)}")
      end
    end
  end
end
