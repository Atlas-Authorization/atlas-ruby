# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AuditEventSchemas < Base
      # List the registered audit event schemas, by action then version (newest first).
      # Scope: audit_events:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/audit_event_schemas", query: query)
      end

      # Register a schema for an action: the target types and actor types it allows and a JSON
      # Schema its metadata must satisfy. +version+ defaults to the next number for that action; a
      # version is immutable (registering it again is a 409) - change a schema by registering a new
      # version. From then on events with this action are validated on write.
      # Scope: audit_events:write. query: dry_run. body requires: action.
      def register(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/audit_event_schemas",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # One audit event schema.
      # Scope: audit_events:read.
      def get(id)
        request(method: :get, path: "/v1/audit_event_schemas/#{enc(id)}")
      end

      # Change a schema version's description or status. A deprecated version is no longer applied
      # by default but still validates events that name it with +schema_version+.
      # Scope: audit_events:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/audit_event_schemas/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove a schema version. Events already recorded keep their +schema_version+ number.
      # Scope: audit_events:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/audit_event_schemas/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Blank named fields of one audit event (replaced by [redacted]) without deleting it:
      # +actor_id+, +target_id+, +target_name+ or +metadata.<dotted.path>+. A +reason+ is required.
      # The redaction is recorded in its own log (GET /v1/audit_events/:id/redactions) and in
      # Atlas's audit log as +audit_event.redacted+ - the fields and the reason, never the removed
      # values.
      # Scope: audit_events:write. query: dry_run. body requires: fields, reason.
      def redact(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/audit_events/#{enc(id)}/redact",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # An audit event's redaction history: which fields were blanked, why, and by which key.
      # Scope: audit_events:read. query: limit, starting_after.
      def redactions(id, query = nil)
        request(method: :get, path: "/v1/audit_events/#{enc(id)}/redactions", query: query)
      end
    end
  end
end
