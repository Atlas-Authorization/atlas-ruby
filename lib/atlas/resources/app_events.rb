# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Application webhooks: send YOUR app's own events (+call.completed+,
    # +invoice.paid+) to endpoints your customers (organizations) register.
    # Atlas signs them (Standard Webhooks: verify with
    # {Atlas::Webhook.verify_standard}), retries, tracks health, auto-disables a
    # dead endpoint and keeps the delivery log with redeliver and replay.
    #
    #   atlas.app_events.types.create({ type: "call.completed", description: "A call finished." })
    #   atlas.app_events.publish({ organization_id: "org_1", type: "call.completed", data: { call_id: "c1" }, idempotency_key: "c1" })
    class AppEvents < Base
      # +POST /v1/app_events+ — publish one event to one organization's subscribed
      # endpoints. Body: +organization_id+ (or +org+), +type+ (from your catalog),
      # +data+ and optional +idempotency_key+ (a repeat with the same key returns the
      # first event and queues nothing; kept 90 days). Returns the event plus
      # +idempotent_replay+ and, on the first publish, +deliveries_queued+ and
      # +endpoint_ids+ (201 new, 200 replay).
      # Scope: app_events:write. query: dry_run.
      def publish(body, query = nil, idempotency_key: nil)
        request(method: :post, path: "/v1/app_events", query: query, body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/app_events+ — one organization's published events, newest first.
      # query: organization_id (required), type, limit, starting_after.
      def list(query)
        request(method: :get, path: "/v1/app_events", query: query)
      end

      # +GET /v1/app_events/:id+ — one published event.
      def get(id)
        request(method: :get, path: "/v1/app_events/#{enc(id)}")
      end

      # Your event catalog (+/v1/app_event_types+).
      def types
        @types ||= Types.new(@transport)
      end

      # One organization's endpoints for your events
      # (+/v1/organizations/:id/app_webhook_endpoints+).
      def endpoints
        @endpoints ||= Endpoints.new(@transport)
      end

      # +/v1/app_event_types+ — an app event type is +{ object: "app_event_type", id
      # (aet_...), type, description, schema (JSON Schema every published data must
      # match; nil = any object), deprecated (still publishable, hidden from the
      # endpoint picker), created_at, updated_at }+. +id_or_type+ is the +aet_+ id or
      # the type name.
      class Types < Base
        def list(query = nil)
          request(method: :get, path: "/v1/app_event_types", query: query)
        end

        # Body: +type+ (lowercase dotted, e.g. +call.completed+), optional
        # +description+, +schema+, +deprecated+. query: dry_run.
        def create(body, query = nil, idempotency_key: nil)
          request(method: :post, path: "/v1/app_event_types", query: query, body: body, idempotency_key: idempotency_key)
        end

        def get(id_or_type)
          request(method: :get, path: "/v1/app_event_types/#{enc(id_or_type)}")
        end

        # Body: +description+, +schema+, +deprecated+. query: dry_run.
        def update(id_or_type, body, query = nil, idempotency_key: nil)
          request(method: :patch, path: "/v1/app_event_types/#{enc(id_or_type)}", query: query, body: body,
                  idempotency_key: idempotency_key)
        end

        def delete(id_or_type, query = nil, idempotency_key: nil)
          request(method: :delete, path: "/v1/app_event_types/#{enc(id_or_type)}", query: query,
                  idempotency_key: idempotency_key)
        end
      end

      # +/v1/organizations/:id/app_webhook_endpoints+ — webhook endpoint objects as
      # for instance webhooks. Body fields: +url+, +enabled_events+ (types from your
      # catalog, or +["*"]+, the default), +description+, +active+.
      class Endpoints < Base
        def list(id, query = nil)
          request(method: :get, path: base(id), query: query)
        end

        # The +whsec_+ secret is in this response only (or {#reveal_secret}).
        # query: dry_run.
        def create(id, body, query = nil, idempotency_key: nil)
          request(method: :post, path: base(id), query: query, body: body, idempotency_key: idempotency_key)
        end

        def get(id, endpoint_id)
          request(method: :get, path: "#{base(id)}/#{enc(endpoint_id)}")
        end

        def update(id, endpoint_id, body, query = nil, idempotency_key: nil)
          request(method: :patch, path: "#{base(id)}/#{enc(endpoint_id)}", query: query, body: body,
                  idempotency_key: idempotency_key)
        end

        def delete(id, endpoint_id, query = nil, idempotency_key: nil)
          request(method: :delete, path: "#{base(id)}/#{enc(endpoint_id)}", query: query,
                  idempotency_key: idempotency_key)
        end

        # The previous secret keeps signing for 24 hours. Returns +{ object:
        # "webhook_secret", secret, overlap_seconds, previous_secret_expires_at }+.
        def rotate_secret(id, endpoint_id, query = nil, idempotency_key: nil)
          request(method: :post, path: "#{base(id)}/#{enc(endpoint_id)}/rotate_secret", query: query,
                  idempotency_key: idempotency_key)
        end

        # Returns +{ object: "webhook_secret", secret }+.
        def reveal_secret(id, endpoint_id, query = nil, idempotency_key: nil)
          request(method: :post, path: "#{base(id)}/#{enc(endpoint_id)}/reveal_secret", query: query,
                  idempotency_key: idempotency_key)
        end

        # Send a test event. query: wait (e.g. +"10s"+ attempts it now and returns
        # the result; otherwise it is queued).
        def test(id, endpoint_id, query = nil, idempotency_key: nil)
          request(method: :post, path: "#{base(id)}/#{enc(endpoint_id)}/test", query: query,
                  idempotency_key: idempotency_key)
        end

        # The delivery log. query: as for instance webhook deliveries (limit,
        # starting_after, status, event_type, since, until, trace).
        def deliveries(id, endpoint_id, query = nil)
          request(method: :get, path: "#{base(id)}/#{enc(endpoint_id)}/deliveries", query: query)
        end

        # Redeliver one past delivery as a fresh attempt. Returns +{ object:
        # "webhook_delivery", id, event_id, status, note }+.
        def redeliver(id, endpoint_id, delivery_id, query = nil, idempotency_key: nil)
          request(method: :post, path: "#{base(id)}/#{enc(endpoint_id)}/deliveries/#{enc(delivery_id)}/redeliver",
                  query: query, idempotency_key: idempotency_key)
        end

        # Re-send what the endpoint missed. Body: +since+ (+"failing_since"+ or
        # epoch), +until+, +event_type+ (the same window as webhook replay).
        def replay(id, endpoint_id, body, query = nil, idempotency_key: nil)
          request(method: :post, path: "#{base(id)}/#{enc(endpoint_id)}/replay", query: query, body: body,
                  idempotency_key: idempotency_key)
        end

        # +GET /v1/organizations/:id/app_event_types+ — the event types this
        # organization can subscribe its endpoints to (the picker list; deprecated
        # types left out).
        def app_event_types(id, query = nil)
          request(method: :get, path: "/v1/organizations/#{enc(id)}/app_event_types", query: query)
        end

        private

        def base(id)
          "/v1/organizations/#{enc(id)}/app_webhook_endpoints"
        end
      end
    end
  end
end
