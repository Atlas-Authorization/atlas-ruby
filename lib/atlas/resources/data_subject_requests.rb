# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/data_subject_requests+ — the GDPR/DSAR admin surface.
    class DataSubjectRequests < Base
      def list(params = {})
        request(method: :get, path: "/v1/data_subject_requests", query: params)
      end

      def get(id)
        request(method: :get, path: "/v1/data_subject_requests/#{enc(id)}")
      end

      # Fulfil a request now — build the export package, or run the erasure.
      def fulfill(id, idempotency_key: nil)
        request(method: :post, path: "/v1/data_subject_requests/#{enc(id)}/fulfill", idempotency_key: idempotency_key)
      end

      # Reject a request with a recorded reason. Terminal.
      def reject(id, body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/data_subject_requests/#{enc(id)}/reject", body: body, idempotency_key: idempotency_key)
      end
    end
  end
end
