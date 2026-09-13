# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/messaging_providers+ — BYOK email/SMS provider config.
    class Messaging < Base
      # The instance's configured email and SMS providers, secrets omitted.
      def get
        request(method: :get, path: "/v1/messaging_providers")
      end

      def set_email(body)
        request(method: :put, path: "/v1/messaging_providers/email", body: body)
      end

      def set_sms(body)
        request(method: :put, path: "/v1/messaging_providers/sms", body: body)
      end

      def delete_channel(channel)
        request(method: :delete, path: "/v1/messaging_providers/#{enc(channel)}")
      end

      # Send a fixed, clearly-marked test message through the channel's provider.
      def test(channel, body)
        request(method: :post, path: "/v1/messaging_providers/#{enc(channel)}/test", body: body)
      end
    end
  end
end
