# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class ScimProvisioningPresets < Base
      # List the pre-built outbound provisioning targets (Slack, GitHub, Zoom, Salesforce,
      # Atlassian) with their base-URL template and required parameters.
      # Scope: scim_provisioning:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/scim_provisioning_presets", query: query)
      end
    end
  end
end
