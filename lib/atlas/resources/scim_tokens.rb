# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/scim_tokens+ — inbound SCIM bearer tokens for directory sync.
    class ScimTokens < Base
      def list
        request(method: :get, path: "/v1/scim_tokens")
      end

      # Create reveals the usable secret exactly once.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/scim_tokens", body: body, idempotency_key: idempotency_key)
      end

      def revoke(id)
        request(method: :post, path: "/v1/scim_tokens/#{enc(id)}/revoke")
      end
    end
  end
end
