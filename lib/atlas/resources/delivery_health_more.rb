# frozen_string_literal: true

require_relative "misc_v2"

module Atlas
  module Resources
    class DeliveryHealth
      # Delivery health of one target. 404 until a delivery to it has been recorded.
      # Scope: webhooks:read.
      def get_scope(kind, id)
        request(method: :get, path: "/v1/delivery_health/#{enc(kind)}/#{enc(id)}")
      end
    end
  end
end
