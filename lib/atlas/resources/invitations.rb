# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/invitations+ — instance-level sign-up invitations.
    class Invitations < Base
      def list(params = {})
        request(method: :get, path: "/v1/invitations", query: params)
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/invitations", body: body, idempotency_key: idempotency_key)
      end

      def revoke(id)
        request(method: :post, path: "/v1/invitations/#{enc(id)}/revoke")
      end
    end
  end
end
