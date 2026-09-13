# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/localizations+ — per-locale overrides for emails, SMS, and prompt copy.
    class Localizations < Base
      def list(params = {})
        request(method: :get, path: "/v1/localizations", query: params)
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/localizations", body: body, idempotency_key: idempotency_key)
      end

      def get(id)
        request(method: :get, path: "/v1/localizations/#{enc(id)}")
      end

      def update(id, body)
        request(method: :patch, path: "/v1/localizations/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/localizations/#{enc(id)}")
      end
    end
  end
end
