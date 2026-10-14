# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/organization_settings_schema+ — the JSON Schema organization settings are validated against.
    class OrganizationSettingsSchema < Base
      # +GET /v1/organization_settings_schema+ — the instance-wide JSON Schema for organization settings.
      def get
        request(method: :get, path: "/v1/organization_settings_schema")
      end

      # +POST /v1/organization_settings_schema+ — register the organization settings JSON Schema (first registration).
      def create(schema, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/organization_settings_schema",
          body: { schema: schema },
          idempotency_key: idempotency_key
        )
      end

      # +PUT /v1/organization_settings_schema+ — replace the organization settings JSON Schema (bumps its version).
      def replace(schema, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/organization_settings_schema",
          body: { schema: schema },
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
