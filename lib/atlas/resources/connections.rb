# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Connections < Base
      # Define a connection: an owner (an organization or a user) and a third-party API. +kind+ is
      # oauth (rides a linked provider account; for an organization, the account of the member who
      # shared it), api_key or client_credentials (a credential the owner enters). +allowed_hosts+
      # lists the only hosts the relay may call. An owner may hold several connections of one
      # provider (one per provider account): create one per account, then call +POST
      # /v1/connections/{id}/connect+. A connection is never a sign-in method.
      # Scope: organizations:write. query: dry_run. body requires: owner, kind, provider,
      # allowed_hosts.
      def create(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List connections, newest first, with each one's live status. Filter by owner or provider.
      # Scope: organizations:read. query: owner_type, owner_id, provider, environment, status,
      # starting_after, limit.
      def list(query = nil)
        request(method: :get, path: "/v1/connections", query: query)
      end

      # Read one connection with its current status.
      # Scope: organizations:read.
      def get(id)
        request(method: :get, path: "/v1/connections/#{enc(id)}")
      end

      # Rename a connection, change its allowed hosts or settings, transfer it to another owner with
      # +owner+ (the stored tokens move with it, no reconnect), change +environment+ or
      # +host_params+ (an oauth connection that already holds a token becomes needs_reauth, because
      # the token belongs to the old host), or (organization-owned oauth) set +shared_by_user_id+ to
      # copy that member's linked account into the connection.
      # Scope: organizations:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/connections/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a connection and its stored credential (204). With +revoke=true+ the token is first
      # revoked at the provider and the answer is 200 with what the provider said (provider_revoked
      # true, false or "unsupported", provider_error, local_cleared); the connection is deleted
      # either way.
      # Scope: organizations:write. query: dry_run, revoke.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/connections/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Enter the credential for a non-OAuth connection (api_key, bearer, basic, custom_header,
      # hmac_secret, client_credentials, jwt_bearer, oauth1, github_app_installation). Write-only:
      # it is sealed in the vault and never returned. Replaces the earlier credential as a new vault
      # version; use POST .../credentials/rotate to keep the old version valid for an overlap
      # window.
      # Scope: organizations:write. query: dry_run.
      def set_credentials(id, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/connections/#{enc(id)}/credentials",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Start the provider authorization for this connection and return the URL to send the owner
      # to. The tokens are stored on the connection itself, never on a user: no external account is
      # created, no sign-in method is added, no email is proven and no step-up is needed.
      # +host_params+ fill the provider's host templates for this connection (validated against a
      # per-provider allowlist; 400 +host_params.<key>+ otherwise). Reconnecting the same provider
      # account updates the same connection; a different account answers 409 unless +create_if_new+
      # is true. An owner OAuth client (+PUT /v1/connections/oauth_clients+) overrides the instance
      # client.
      # Scope: organizations:write. query: dry_run. body requires: redirect_url.
      def connect(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/connect",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Revoke the stored token at the provider, delete it from the vault and mark the connection
      # revoked (connection.revoked is sent once). The response is the connection plus what the
      # provider said: provider_revoked is true only when it confirmed, "unsupported" when it has no
      # revoke endpoint, false when it refused or was unreachable (provider_error says why). The
      # local token is cleared in every case. Connect again to use it.
      # Scope: organizations:write. query: dry_run.
      def revoke(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/revoke",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Have Atlas sign a request with an oauth1 connection (NetSuite token-based authentication:
      # HMAC-SHA256 with the realm; X Ads and other three-legged providers: HMAC-SHA1) and return
      # the +Authorization: OAuth ...+ header. The consumer and token secrets never leave Atlas. The
      # URL must be https on an allowed host; a form-encoded body is part of the signature. Needs
      # connections:sign.
      # Scope: connections:sign. query: dry_run. body requires: url.
      def oauth1_sign(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/oauth1/sign",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Make a provider API call server-side with this connection's credential, so the credential
      # never reaches your code: Atlas injects an api_key (header or query), bearer, basic or custom
      # header, signs with an hmac_secret or OAuth 1.0a, or sends a minted client_credentials /
      # jwt_bearer / GitHub App installation / admin consent token. Only https calls to the
      # connection's allowed_hosts are made, with the verbs in allowed_methods (default GET, HEAD,
      # POST). When the connection is not connected, or the provider rejects the credential, the
      # answer is 402 CONNECTION_REQUIRED with +meta.reason+ (not_connected or needs_reauth) and,
      # for a user-owned OAuth connection when you pass +redirect_url+, +meta.authorize_url+. The
      # audit log records the method, host and status only.
      # Scope: oauth_tokens:read. query: dry_run. body requires: url.
      def relay(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/relay",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # The connection's live token for your backend. An oauth connection's token is refreshed first
      # when it is expired or about to be (single-flight across processes, using the client that
      # issued it and the connection's host_params). Built for sync workers: the response carries an
      # +ETag+ and +Cache-Control: private, max-age=<seconds until just before expires_at>+, so
      # cache it until then; send +If-None-Match+ and an unchanged, still-valid token answers 304
      # with no body and no vault read; +min_ttl_seconds+ refreshes first when less than that much
      # validity remains. A grant connection (client_credentials, jwt_bearer,
      # github_app_installation, admin_consent) has its token minted from the credential Atlas holds
      # instead, answered with +Cache-Control: no-store+ (no ETag); pass +subject+ to a jwt_bearer
      # connection to act as that user (Google domain-wide delegation). Includes the captured
      # handles (+metadata+, +token_response+) and any further named credentials. 402
      # CONNECTION_REQUIRED with +meta.reason+ not_connected, needs_reauth, revoked or
      # refresh_failed when there is no usable token. When the provider answers 401 to the token,
      # call +POST /v1/connections/{id}/token/refresh+ instead of re-reading. Rate limit: 6,000
      # reads per minute per secret key and 300 per minute per connection (RateLimit-* headers on
      # every response, 429 with Retry-After beyond them). Reads are audited as
      # connection.token_read once per connection per minute with the read count (a read that
      # refreshed is always audited); the token itself is never logged.
      # Scope: connections:token. query: min_ttl_seconds, subject, refresh.
      def token(id, query = nil)
        request(method: :get, path: "/v1/connections/#{enc(id)}/token", query: query)
      end

      # Force a refresh after the provider refused the access token (401). Single-flight: however
      # many callers saw the same 401, the provider is called once. Send +stale_token_hash+
      # (lowercase hex SHA-256 of the access token you were refused with); if the stored token is
      # already a different one, a peer has refreshed and the current token is returned without
      # calling the provider (+refreshed: false+). Same body, ETag and 402 behaviour as the token
      # read; the response is never cached. Counts against the same rate limit as the token read.
      # Scope: connections:token. query: dry_run.
      def refresh_token(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/token/refresh",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read the tokens of up to 100 connections in one call (min_ttl_seconds applies to each). Each
      # id gets its own result: status ok with the token, or status error with a code and reason
      # (not_connected, needs_reauth, revoked, refresh_failed, unknown_connection), so one dead
      # connection never fails the batch. The response is never cached. Counts once against the
      # token-read rate limit.
      # Scope: connections:token. query: dry_run. body requires: ids.
      def tokens(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/tokens/batch",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Bulk-import existing provider refresh tokens as connections, up to 500 rows, so nobody
      # reconnects. Each row: provider, owner, external_id (the provider-side account: how a
      # re-import finds the same connection), refresh_token (or access_token), and optionally
      # scopes, metadata, environment, host_params, name, allowed_hosts. By default (validate true)
      # each refresh token is spent once against the provider with the OAuth client that will own
      # the connection, and the tokens the provider issues are stored, so the imported copy stops
      # being current on a rotating provider. A failing row creates and changes nothing. dry_run
      # checks shapes only and never calls the provider. Idempotent on Idempotency-Key. Tokens go
      # straight to the vault and never appear in the answer or the audit log.
      # Scope: connections:import. query: dry_run. body requires: connections.
      def import_connections(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/import",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Export connections. Without include_secrets: metadata only (provider, owner, account,
      # environment, scopes, status), scope connections:export. With include_secrets: needs scope
      # connections:export_secrets, the header X-Atlas-Confirm: export-secrets and
      # recipient_public_key (a public JWK: RSA of 3072 bits or more, or EC P-256/384/521). The
      # tokens come back as one compact JWE sealed to that key that only its holder can open; Atlas
      # keeps no plaintext. Pages hold up to 200 connections with secrets (500 without); follow
      # next_cursor with starting_after. Every export is audited with its count, never the secrets.
      # Opened, each connection is a valid import row.
      # Scope: connections:export. query: dry_run.
      def export_connections(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/export",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read the credential an api_key, bearer, basic, custom_header or hmac_secret connection
      # stores, for your backend. Needs the dedicated connections:secret_read scope; every read is
      # audited as connection.secret.read with the caller, connection and version (never the value)
      # and the response is +Cache-Control: no-store+. +version+ is current (default), previous
      # (only while a rotation's overlap window is open) or a version number. A signing grant's
      # private key is never readable: 409 +not_readable+. There is no browser or session route that
      # reads a credential.
      # Scope: connections:secret_read. query: version.
      def secret(id, query = nil)
        request(method: :get, path: "/v1/connections/#{enc(id)}/secret", query: query)
      end

      # The vault versions of a connection's entered credential (numbers and times only, never
      # values) and the open rotation window.
      # Scope: organizations:read. query: limit, starting_after.
      def secret_versions(id, query = nil)
        request(method: :get, path: "/v1/connections/#{enc(id)}/credentials/versions", query: query)
      end

      # Rotate the credential: the body is the new credential (the same fields as PUT credentials).
      # It becomes the current vault version; the replaced one stays valid for +overlap_seconds+
      # (default 3600, up to 30 days): the relay falls back to it when the provider refuses the new
      # one, and GET secret?version=previous returns it. +expires_at+ sets the new credential's
      # expiry. The secret never reaches the audit log.
      # Scope: organizations:write. query: dry_run.
      def rotate_credentials(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/connections/#{enc(id)}/credentials/rotate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def oauth_clients
        @oauth_clients ||= OauthClients.new(@transport)
      end

      def webhooks
        @webhooks ||= Webhooks.new(@transport)
      end

      class OauthClients < Base
        # Set an owner's own OAuth client (their registered app) for a provider and environment. It
        # overrides the instance client for that owner's connections to connect and to refresh.
        # Write-only secret, sealed in the vault. Creates the client or replaces it.
        # Scope: organizations:write. query: dry_run. body requires: provider, client_id.
        def set(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/connections/oauth_clients",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # List owner OAuth clients. The secret is never returned.
        # Scope: organizations:read. query: owner_type, owner_id, provider, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/connections/oauth_clients", query: query)
        end

        # Read one owner OAuth client.
        # Scope: organizations:read.
        def get(id)
          request(method: :get, path: "/v1/connections/oauth_clients/#{enc(id)}")
        end

        # Delete an owner OAuth client and its sealed secret. 409 while connections still hold
        # tokens it issued (they could no longer refresh).
        # Scope: organizations:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/connections/oauth_clients/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Webhooks < Base
        # Verify a provider webhook signature with the connection's secret (the endpoint's own
        # signing secret, else the connection's hmac_secret, else its OAuth client secret). Schemes:
        # hubspot_v3 (needs method and url), shopify_hmac, intercom, zoom, slack_v0, calendly,
        # stripe, generic_hmac_sha256. Constant-time comparison; a signed timestamp must be within
        # the tolerance (5 minutes, Calendly 3); a delivery id or signature already seen on the
        # connection answers +replayed+. Send the body exactly as received (+raw_body+, or base64
        # with raw_body_encoding). Zoom and Slack handshakes come back in +handshake+. Needs
        # connections:webhook_verify.
        # Scope: connections:webhook_verify. query: dry_run. body requires: scheme, headers,
        # raw_body.
        def verify(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/connections/#{enc(id)}/webhooks/verify",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Create a webhook ingress endpoint on a connection. Point the provider at +ingress_url+;
        # Atlas verifies each delivery, refuses forged, stale and replayed ones, answers Zoom and
        # Slack handshakes, and forwards only genuine deliveries to +forward_url+ as Atlas-signed
        # webhooks (atlas-id, atlas-timestamp, atlas-signature with +forward_secret+, returned
        # once). Bodies over 1 MiB are refused; the ingress is rate limited.
        # Scope: organizations:write. query: dry_run. body requires: scheme, forward_url.
        def create_endpoint(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/connections/#{enc(id)}/webhook_endpoints",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # List a connection's webhook ingress endpoints.
        # Scope: organizations:read. query: limit, starting_after.
        def list_endpoints(id, query = nil)
          request(method: :get, path: "/v1/connections/#{enc(id)}/webhook_endpoints", query: query)
        end

        # Change an endpoint's forward_url, enabled flag or signing secret.
        # Scope: organizations:write. query: dry_run.
        def update_endpoint(id, endpoint_id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/connections/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a webhook ingress endpoint and its secrets.
        # Scope: organizations:write. query: dry_run.
        def delete_endpoint(id, endpoint_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/connections/#{enc(id)}/webhook_endpoints/#{enc(endpoint_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
