# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sso_onboarding_profiles+ — self-service SSO onboarding profiles and
    # the one-time tickets they issue.
    class SsoOnboarding < Base
      # +name:+ lists only the profiles with exactly that name ("find or create").
      def list(name: nil)
        request(method: :get, path: "/v1/sso_onboarding_profiles", query: name.nil? ? nil : { name: name })
      end

      def get(id)
        request(method: :get, path: "/v1/sso_onboarding_profiles/#{enc(id)}")
      end

      # +body+ may carry +return_url+: where "Finish" on the hosted setup page
      # sends the admin (https, on one of your allowed origins).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sso_onboarding_profiles", body: body, idempotency_key: idempotency_key)
      end

      def delete(id)
        request(method: :delete, path: "/v1/sso_onboarding_profiles/#{enc(id)}")
      end

      # Issue a one-time ticket for a profile. The token is returned once, here.
      # +body+: +organization_id+, +expires_in_seconds+ (clamped to 300..2592000,
      # default 3 days) and +return_url+ (overrides the profile's). The answer
      # carries +effective_return_url+.
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
