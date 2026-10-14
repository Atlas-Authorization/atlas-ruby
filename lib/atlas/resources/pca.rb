# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/pca+ — proof-carrying authority controls: attestors, kill switch, revocations, step-ups.
    class Pca < Base
      # +GET /v1/pca/attestors+ — the trusted software-attestor public keys.
      def get_attestors
        request(method: :get, path: "/v1/pca/attestors")
      end

      # +PUT /v1/pca/attestors+ — replace the trusted software-attestor key list.
      def set_attestors(trusted_attestor_keys)
        request(method: :put, path: "/v1/pca/attestors", body: { trusted_attestor_keys: trusted_attestor_keys })
      end

      # +POST /v1/pca/freeze+ — engage the instance-wide kill switch: every proof-carrying action is denied until cleared.
      def engage_kill_switch(body = {})
        request(method: :post, path: "/v1/pca/freeze", body: body)
      end

      # +DELETE /v1/pca/freeze+ — clear the instance-wide kill switch.
      def clear_kill_switch
        request(method: :delete, path: "/v1/pca/freeze")
      end

      # +POST /v1/pca/revocations+ — revoke a capability id under a grant (grant_ref, cap_id).
      def revoke(body)
        request(method: :post, path: "/v1/pca/revocations", body: body)
      end

      # +POST /v1/pca/stepups/:id/deny+ — deny a pending step-up.
      def deny_step_up(id, body = {})
        request(method: :post, path: "/v1/pca/stepups/#{enc(id)}/deny", body: body)
      end
    end
  end
end
