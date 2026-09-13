# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/log_streams+ — the instance event feed forwarded to external sinks.
    class LogStreams < Base
      def list
        request(method: :get, path: "/v1/log_streams")
      end

      def get(id)
        request(method: :get, path: "/v1/log_streams/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/log_streams", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/log_streams/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/log_streams/#{enc(id)}")
      end

      # Send ONE synthetic event with the real credentials.
      def test(id)
        request(method: :post, path: "/v1/log_streams/#{enc(id)}/test")
      end
    end
  end
end
