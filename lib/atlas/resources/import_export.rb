# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/user_imports+, +/v1/user_exports+, +/v1/jobs+ — bulk user import/export
    # jobs (the Auth0 +jobs+ parity surface).
    class ImportExport < Base
      # Import users through the same per-row path sign-up uses.
      def import_users(body, idempotency_key: nil)
        request(method: :post, path: "/v1/user_imports", body: body, idempotency_key: idempotency_key)
      end

      # Export every non-deleted user, serialised without secrets.
      def export_users(idempotency_key: nil)
        request(method: :post, path: "/v1/user_exports", idempotency_key: idempotency_key)
      end

      # Poll the instance's import/export jobs, newest first.
      def list_jobs(params = {})
        request(method: :get, path: "/v1/jobs", query: params)
      end

      def get_job(id)
        request(method: :get, path: "/v1/jobs/#{enc(id)}")
      end

      # The per-row failures recorded against a job.
      def get_job_errors(id)
        request(method: :get, path: "/v1/jobs/#{enc(id)}/errors")
      end
    end
  end
end
