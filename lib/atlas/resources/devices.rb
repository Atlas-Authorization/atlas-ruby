# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Devices < Base
      # List registered devices, filtered by user_id or source.
      # Scope: users:read. query: user_id, source, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/devices", query: query)
      end

      # Create or refresh one device by (source, external_id), reporting managed/compliant posture.
      # Tie it to a user with user_id or a verified user_email. Access policies read the result
      # through the deviceTrust condition: trusted = a managed, compliant device reported within 30
      # days.
      # Scope: users:write. query: dry_run.
      def report(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(method: :put, path: "/v1/devices", query: query, body: body, idempotency_key: idempotency_key)
      end

      # Fetch a device and its latest posture.
      # Scope: users:read.
      def get(id)
        request(method: :get, path: "/v1/devices/#{enc(id)}")
      end

      # Remove a device from the registry.
      # Scope: users:write. query: dry_run.
      def remove(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/devices/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Posture ingestion for your MDM/EDR or its relay: up to 500 device reports per call, same
      # fields as PUT /v1/devices.
      # Scope: users:write. query: dry_run.
      def ingest_posture(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/device_posture",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
