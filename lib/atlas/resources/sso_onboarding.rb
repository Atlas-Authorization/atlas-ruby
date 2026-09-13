# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sso_onboarding_profiles+ — self-service SSO onboarding profiles and
    # the one-time tickets they issue.
    class SsoOnboarding < Base
      def list
        request(method: :get, path: "/v1/sso_onboarding_profiles")
      end

      def get(id)
        request(method: :get, path: "/v1/sso_onboarding_profiles/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sso_onboarding_profiles", body: body, idempotency_key: idempotency_key)
      end

      def delete(id)
        request(method: :delete, path: "/v1/sso_onboarding_profiles/#{enc(id)}")
      end

      # Issue a one-time ticket for a profile. The token is returned once, here.
      def create_ticket(profile_id, body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/sso_onboarding_profiles/#{enc(profile_id)}/tickets", body: body, idempotency_key: idempotency_key)
      end

      # Kill a still-live ticket. 404 once used, expired, or already revoked.
      def revoke_ticket(ticket_id)
        request(method: :post, path: "/v1/sso_onboarding_tickets/#{enc(ticket_id)}/revoke")
      end
    end
  end
end
