# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/managed_waf+ — the managed AWS WAF captcha gate control plane.
    class ManagedWaf < Base
      # Read config + provisioning state, with secrets reduced to +has_*+ markers.
      def get
        request(method: :get, path: "/v1/managed_waf")
      end

      # Read just the provisioning state.
      def status
        request(method: :get, path: "/v1/managed_waf/status")
      end

      # Set config and write-only credentials; omitted fields are left unchanged.
      def update(body)
        request(method: :put, path: "/v1/managed_waf", body: body)
      end

      # Apply now — idempotent create/update + associate the WebACL.
      def provision
        request(method: :post, path: "/v1/managed_waf/provision")
      end

      # Disassociate and delete the WebACL.
      def deprovision
        request(method: :post, path: "/v1/managed_waf/deprovision")
      end
    end
  end
end
