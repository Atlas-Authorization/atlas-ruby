# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Listen < Base
      # Start a local webhook forwarding session (what +atlas listen+ uses). Returns a session id, a
      # signing secret for that session only (it is unrelated to any registered endpoint's secret)
      # and the stream URL. The session needs no storage: it expires at +expires_at+ (default 1
      # hour, +ttl_seconds+ 60 to 43200).
      # Scope: webhooks:write. query: dry_run.
      def create_session(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/listen/sessions",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Server-Sent Events stream of the instance's new events for a listen session. Each +webhook+
      # event carries +{id, type, headers, body}+: the headers (+atlas-id+, +atlas-timestamp+,
      # +atlas-signature+) and the exact JSON body of a would-be delivery, signed with the session
      # secret. Starts at "now" unless resumed with +Last-Event-ID+ or +after+. Query: +events+
      # (comma-separated types or patterns), +max_events+ and +max_wait_seconds+ (end the stream
      # early, for scripts and CI). A +: keep-alive+ comment is sent every 15 seconds; an +expired+
      # event ends the stream at the session expiry. 404 for an unknown session id, 400 once
      # expired.
      # Scope: webhooks:read. query: events, after, max_events, poll_ms, max_wait_seconds. Returns
      # the raw text/event-stream body as a String.
      def stream_session(id, query = nil)
        request(method: :get, path: "/v1/listen/sessions/#{enc(id)}/stream", query: query, raw: true)
      end
    end
  end
end
