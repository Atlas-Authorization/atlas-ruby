# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/webhook_endpoints+ — outbound webhook endpoints and their delivery log.
    class Webhooks < Base
      # +webhooks.endpoints+ — CRUD over endpoints.
      def endpoints
        @endpoints ||= Endpoints.new(@transport)
      end

      # Delivery log for an endpoint, newest first. +params+: +limit+ (up to 1000,
      # default 50), +status+, +event_type+, +since+, +until+, +starting_after+
      # (cursor; reads +next_cursor+). Rows carry +latency_ms+ and +trace_id+.
      def deliveries(id, params = {})
        request(method: :get, path: "/v1/webhook_endpoints/#{enc(id)}/deliveries", query: params)
      end

      # +GET /v1/delivery_health+ — see {Atlas::Resources::DeliveryHealth}.
      def delivery_health
        @delivery_health ||= Atlas::Resources::DeliveryHealth.new(@transport)
      end

      # +GET /v1/meta/egress_ips+ — the IPs Atlas delivers webhooks from.
      def egress_ips
        request(method: :get, path: "/v1/meta/egress_ips")
      end

      # Endpoint objects carry +event_naming+ (+canonical+ / +legacy+ / +both+),
      # +external+, +signature_versions+ (+v1+, +v2+), +destination+ (+type+, ...,
      # +credentials_set+), +description+, +health+, +last_success_at+,
      # +last_failure+, +last_failing_since+ (epoch ms; the start of the most recent failure
      # streak, kept after recovery), +consecutive_failures+, +success_rate_24h+,
      # +attempts_24h+, +alert_contacts+, +alerts_sent+, +auto_disable+,
      # +replay+, +metadata+, +external_ref+, +created+ and +updated_at+.
      # Create / update bodies take +destination+, +destination_credentials+
      # (write-only), +alert_contacts+, +external+, +event_naming+,
      # +signature_versions+, +description+, +metadata+ and +external_ref+.
      class Endpoints < Base
        # +params+: +limit+, +starting_after+, and a +metadata:+ Hash filter
        # (sent as +metadata[key]=value+).
        def list(params = {})
          request(method: :get, path: "/v1/webhook_endpoints", query: Atlas::Resources.metadata_query(params))
        end

        # +GET /v1/webhook_endpoints/:id+ — one endpoint with its health fields.
        def get(id)
          request(method: :get, path: "/v1/webhook_endpoints/#{enc(id)}")
        end

        # Create reveals the signing secret (+whsec_...+) exactly once.
        # +dry_run: true+ validates and writes nothing.
        def create(body, idempotency_key: nil, dry_run: false)
          request(method: :post, path: "/v1/webhook_endpoints", body: body, idempotency_key: idempotency_key,
                  query: Atlas::Resources.dry_run_query(dry_run))
        end

        # +PUT /v1/webhook_endpoints/by_url+ — create or update the endpoint for a URL
        # (idempotent; the secret is revealed only when it is created).
        def put_by_url(body, idempotency_key: nil)
          request(method: :put, path: "/v1/webhook_endpoints/by_url", body: body, idempotency_key: idempotency_key)
        end

        def delete(id)
          request(method: :delete, path: "/v1/webhook_endpoints/#{enc(id)}")
        end

        # +PATCH /v1/webhook_endpoints/:id+ — update an endpoint's url, enabled_events or active flag. The signing secret is kept.
        def update(id, body)
          request(method: :patch, path: "/v1/webhook_endpoints/#{enc(id)}", body: body)
        end

        # +POST /v1/webhook_endpoints/:id/reveal_secret+ — show the endpoint's current signing secret again. Does not change it.
        def reveal_secret(id)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/reveal_secret")
        end

        # +POST /v1/webhook_endpoints/:id/rotate_secret+ — rotate the signing secret. The new secret is shown once.
        # By default the old secret stops signing at once. With +{ overlap_seconds: }+ (at most 604800) every
        # delivery is signed with both until +previous_secret_expires_at+ (epoch ms), so a verifier holding
        # either passes. Choose an overlap only once every receiver accepts several signatures (0.7.0+).
        def rotate_secret(id, body = Atlas::Transport::OMIT)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/rotate_secret", body: body)
        end

        # +POST /v1/webhook_endpoints/:id/test+ — send a synthetic webhook.test event to this endpoint only.
        # +wait:+ (seconds) holds the call until the attempt finishes and returns its outcome.
        def test(id, wait: nil)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/test", query: wait.nil? ? nil : { wait: wait })
        end

        # +POST /v1/webhook_endpoints/:id/redeliver+ — redeliver matching past events
        # (body: +event_ids+ / +since+ / +until+ / +event_type+). +since+ is epoch ms or
        # {Atlas::WEBHOOK_REPLAY_SINCE_FAILING} (+"failing_since"+): the start of the
        # endpoint's last failure streak.
        def redeliver(id, body = {}, idempotency_key: nil)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/redeliver", body: body, idempotency_key: idempotency_key)
        end

        # +POST /v1/webhook_endpoints/:id/replay+ — replay events from a point in time
        # (body: +since+, ...) to a recovered endpoint. +since: "failing_since"+ replays
        # everything since the endpoint started failing; it resolves from the live
        # +failing_since+, else +disabled_at+, else +last_failing_since+ (kept after the
        # endpoint recovers or is re-enabled), and is a 400 when the endpoint never failed.
        def replay(id, body = {}, idempotency_key: nil)
          request(method: :post, path: "/v1/webhook_endpoints/#{enc(id)}/replay", body: body, idempotency_key: idempotency_key)
        end
      end

      # +POST /v1/webhook_endpoints/:id/deliveries/:deliveryId/redeliver+ — redeliver a past event as a fresh attempt.
      def redeliver(endpoint_id, delivery_id)
        request(
          method: :post,
          path: "/v1/webhook_endpoints/#{enc(endpoint_id)}/deliveries/#{enc(delivery_id)}/redeliver"
        )
      end
    end
  end
end
