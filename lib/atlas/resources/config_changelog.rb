# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/config_changelog+ — who changed which configuration, and when.
    class ConfigChangelog < Base
      # +GET /v1/config_changelog+ — configuration change history (who changed what, when, with a diff). Cursor-paginated.
      def list(params = {})
        request(method: :get, path: "/v1/config_changelog", query: params)
      end
    end
  end
end
