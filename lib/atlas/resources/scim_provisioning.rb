# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/scim_provisioning_targets+ — OUTBOUND SCIM provisioning targets Atlas
    # pushes users/groups to.
    class ScimProvisioning < Base
      def list
        request(method: :get, path: "/v1/scim_provisioning_targets")
      end

      def get(id)
        request(method: :get, path: "/v1/scim_provisioning_targets/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/scim_provisioning_targets", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/scim_provisioning_targets/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/scim_provisioning_targets/#{enc(id)}")
      end

      # Probe connectivity + auth to the downstream with the real bearer.
      def test(id)
        request(method: :post, path: "/v1/scim_provisioning_targets/#{enc(id)}/test")
      end

      # Force one user's sync now (backfill / re-push).
      def sync_user(id, user_id)
        request(method: :post, path: "/v1/scim_provisioning_targets/#{enc(id)}/sync_user", body: { user_id: user_id })
      end

      # Force one org's (group) sync now.
      def sync_group(id, organization_id)
        request(method: :post, path: "/v1/scim_provisioning_targets/#{enc(id)}/sync_group", body: { organization_id: organization_id })
      end
    end
  end
end
