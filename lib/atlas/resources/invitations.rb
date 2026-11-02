# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/invitations+ — instance-level sign-up invitations.
    class Invitations < Base
      def list(params = {})
        request(method: :get, path: "/v1/invitations", query: params)
      end

      # Body: +email_address+, +public_metadata+, and +expires_at+ (epoch ms or
      # ISO 8601, at most 365 days ahead) or +expires_in_days+ (1-365); default
      # 7 days. Emits +invitation.created+ (then +invitation.accepted+ /
      # +invitation.revoked+).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/invitations", body: body, idempotency_key: idempotency_key)
      end

      def revoke(id)
        request(method: :post, path: "/v1/invitations/#{enc(id)}/revoke")
      end

      # +POST /v1/invitations/bulk+ — create up to 100 invitations; returns created entries and per-entry errors.
      def bulk_create(invitations)
        request(method: :post, path: "/v1/invitations/bulk", body: { invitations: invitations })
      end
    end
  end
end
