# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/data_subject_requests+ — the GDPR/DSAR admin surface.
    #
    # A request carries +canonical_type+ / +canonicalType+, +source+ (for example
    # +api+), +detail+, +case_id+, +external_case+, +trace_id+, +steps+,
    # +retention+ and +deletion_effective_at+. +type+ is +access+, +deletion+,
    # +closure+, +restriction+, +rectification+ (create also accepts +erase+).
    # The data-rights executor protocol lives on {Atlas::Resources::Privacy}.
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

      # +POST /v1/data_subject_requests+ — open an export or erasure request for a user (by user_id or subject_email).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/data_subject_requests", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/data_subject_requests/:id/cancel+ — cancel a scheduled erasure within its grace window.
      def cancel(id, idempotency_key: nil)
        request(method: :post, path: "/v1/data_subject_requests/#{enc(id)}/cancel", idempotency_key: idempotency_key)
      end
    end
  end
end
