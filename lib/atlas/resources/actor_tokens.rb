# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/actor_tokens+ — impersonation tokens (act-as another subject).
    class ActorTokens < Base
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/actor_tokens", body: body, idempotency_key: idempotency_key)
      end

      def revoke(id)
        request(method: :post, path: "/v1/actor_tokens/#{enc(id)}/revoke")
      end
    end
  end
end
