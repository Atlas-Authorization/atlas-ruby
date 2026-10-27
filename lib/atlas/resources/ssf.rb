# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Ssf < Base
      def streams
        @streams ||= Streams.new(@transport)
      end

      def receivers
        @receivers ||= Receivers.new(@transport)
      end

      class Streams < Base
        # List the Shared Signals streams this instance transmits on (push and poll), with their
        # delivery method, requested events and status.
        # Scope: ssf:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/ssf/streams", query: query)
        end

        # Create a stream. +delivery_method+ is +push+ (we POST each signed SET to +endpoint_url+,
        # with the optional +authorization_header+) or +poll+ (the receiver pulls from the returned
        # +poll_endpoint+ with the one-time +poll_token+). +events_requested+ limits the events sent
        # (empty = all supported). SETs are signed with the instance signing key.
        # Scope: ssf:write. query: dry_run.
        def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/ssf/streams",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read a stream, including how many events are waiting to be delivered or acknowledged.
        # Scope: ssf:read.
        def get(id)
          request(method: :get, path: "/v1/ssf/streams/#{enc(id)}")
        end

        # Change a stream: its events, endpoint, authorization header, description, or status
        # (+enabled+, +paused+, +disabled+). A paused stream stops receiving new events.
        # Scope: ssf:write. query: dry_run.
        def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/ssf/streams/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a stream and its queued events.
        # Scope: ssf:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/ssf/streams/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Queue an SSF verification event carrying +state+, so a receiver can confirm the stream
        # works end to end.
        # Scope: ssf:write. query: dry_run.
        def verify(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/ssf/streams/#{enc(id)}/verify",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # The stream's delivery status: enabled, paused or disabled (SSF stream status).
        # Scope: ssf:read.
        def get_status(id)
          request(method: :get, path: "/v1/ssf/streams/#{enc(id)}/status")
        end

        # Set the stream's delivery status to enabled, paused or disabled. A paused stream collects
        # nothing.
        # Scope: ssf:write. query: dry_run.
        def update_status(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/ssf/streams/#{enc(id)}/status",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # The stream's recent events with delivery status, attempts and the last error (the
        # dashboard activity view).
        # Scope: ssf:read. query: limit, starting_after.
        def events(id, query = nil)
          request(method: :get, path: "/v1/ssf/streams/#{enc(id)}/events", query: query)
        end
      end

      class Receivers < Base
        # List inbound Shared Signals receivers: transmitters whose signed events act on this
        # instance's users.
        # Scope: ssf:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/ssf/receivers", query: query)
        end

        # Register a transmitter. Its SETs are POSTed (+application/secevent+jwt+) to the returned
        # +receive_endpoint+ and verified against +jwks_uri+, +issuer+ and the optional +audience+.
        # +actions+ maps an event type URI to +revoke_sessions+, +refresh_claims+ (invalidate minted
        # tokens so the next refresh carries fresh claims, sessions stay), +ban+ or +ignore+;
        # unmapped events are ignored. The default maps session-revoked, credential-change,
        # credential-compromise and device-compliance-change (only when the new status is
        # not-compliant) to +revoke_sessions+, token-claims-change to +refresh_claims+ and
        # account-disabled to +ban+.
        # Scope: ssf:write. query: dry_run.
        def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/ssf/receivers",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Change a receiver: name, JWKS URI, audience, action mapping, or enabled.
        # Scope: ssf:write. query: dry_run.
        def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/ssf/receivers/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete an inbound SSF receiver; its endpoint stops accepting events.
        # Scope: ssf:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/ssf/receivers/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
