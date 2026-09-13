# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/bot_signals+ — export the anti-bot signal lake and its training labels,
    # and add analyst labels.
    class BotSignals < Base
      # Page the signal lake, newest first, for an incremental pull.
      def list(query = nil)
        request(method: :get, path: "/v1/bot_signals", query: query)
      end

      # Page the training labels, newest first.
      def list_labels(query = nil)
        request(method: :get, path: "/v1/bot_labels", query: query)
      end

      # Attach a training label to a user / device / ip_hash / attempt.
      def create_label(body, idempotency_key: nil)
        request(method: :post, path: "/v1/bot_labels", body: body, idempotency_key: idempotency_key)
      end
    end
  end
end
