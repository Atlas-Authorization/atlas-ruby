# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/audit_logs+ — the instance audit trail, cursor-paginated.
    class AuditLogs < Base
      def list(params = {})
        request(method: :get, path: "/v1/audit_logs", query: params)
      end
    end
  end
end
