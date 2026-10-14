# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/legacy_auth_connection+ — lazy migration from a legacy user store at sign-in.
    class LegacyAuthConnection < Base
      # +GET /v1/legacy_auth_connection+ — the lazy-migration connection (configured: false when none). Never the signing secret.
      def get
        request(method: :get, path: "/v1/legacy_auth_connection")
      end

      # +PUT /v1/legacy_auth_connection+ — create or replace the lazy-migration connection (verify_url, signing_secret, enabled, import_on_login, timeout_ms).
      def set(body, idempotency_key: nil)
        request(method: :put, path: "/v1/legacy_auth_connection", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/legacy_auth_connection+ — delete the lazy-migration connection.
      def delete(idempotency_key: nil)
        request(method: :delete, path: "/v1/legacy_auth_connection", idempotency_key: idempotency_key)
      end
    end
  end
end
