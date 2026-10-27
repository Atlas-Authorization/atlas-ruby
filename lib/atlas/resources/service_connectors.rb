# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class ServiceConnectors < Base
      # The services you can connect: for each kind the credential fields, the config fields and the
      # operations with their inputs. Messaging (Twilio, SendGrid, Slack), CRM (HubSpot,
      # Salesforce), analytics (Segment), fraud (Fingerprint, Arkose Labs, Forter, Sardine),
      # identity verification (Persona, Onfido, Veriff, Stripe Identity) and a generic HTTPS
      # connector.
      # Scope: service_connectors:read. query: limit, starting_after.
      def catalog(query = nil)
        request(method: :get, path: "/v1/service_connector_catalog", query: query)
      end

      # List the instance's service connectors. Credentials are never returned.
      # Scope: service_connectors:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/service_connectors", query: query)
      end

      # Connect a service. +credentials+ are checked against the kind's fields and stored in the
      # vault (never returned again); +config+ holds the non-secret settings. 409 when the name is
      # taken.
      # Scope: service_connectors:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/service_connectors",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one service connector.
      # Scope: service_connectors:read.
      def get(id)
        request(method: :get, path: "/v1/service_connectors/#{enc(id)}")
      end

      # Rename, enable or disable a connector, merge new +config+ values, or replace individual
      # +credentials+ (written as a new vault version; the others are kept).
      # Scope: service_connectors:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/service_connectors/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a connector and its stored credentials.
      # Scope: service_connectors:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/service_connectors/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Run one operation of the connector (send a message, read a fraud signal, start an identity
      # check). +input+ is checked against the operation's fields. A refusal or failure from the
      # service is 502 CONNECTOR_UPSTREAM_ERROR with its own message. Each call is audited without
      # its input or output.
      # Scope: service_connectors:invoke. query: dry_run.
      def invoke(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/service_connectors/#{enc(id)}/invoke",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
