# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/audit_events+ — your own custom audit events, streamed to each organization's SIEM.
    class AuditEvents < Base
      # +POST /v1/audit_events+ — write one of your own audit events (actor, action, target, organization_id, occurred_at, metadata).
      def create(body)
        request(method: :post, path: "/v1/audit_events", body: body)
      end

      # +POST /v1/audit_events/batch+ — write up to 100 audit events atomically.
      def create_batch(events)
        request(method: :post, path: "/v1/audit_events/batch", body: { events: events })
      end

      # +GET /v1/audit_events+ — query your audit events, newest first. Cursor-paginated.
      def list(params = {})
        request(method: :get, path: "/v1/audit_events", query: params)
      end

      # +GET /v1/audit_events/export+ — export every matching audit event as one document (format: "jsonl" or "csv"). Returns the raw text.
      def export(params = {})
        request(method: :get, path: "/v1/audit_events/export", query: params, raw: true)
      end

      # +DELETE /v1/audit_events+ — bulk-delete audit events (development instances only), optionally narrowed by organization_id and action.
      def delete_all(params = {})
        request(method: :delete, path: "/v1/audit_events", query: params)
      end
    end
  end
end
