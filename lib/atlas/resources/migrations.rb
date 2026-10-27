# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Migrations < Base
      # Server-to-server exchange of an old +source+ session for an Atlas session, once (what
      # migrationBridge({ source }) calls with the secret key). The token is verified (vendor JWT
      # against the bridge's issuer and keys, or sha256 matched against imported sessions), mapped
      # to the imported user, spent in the single-use ledger and then takes the normal sign-in path
      # (guards, MFA policy, post_login Actions, audit). Returns tokens in the body, or a
      # sign_in_attempt when a second factor is owed. Limited per instance (6000/min), per end-user
      # IP (60/min) and per user (10/min). Send the end user's IP / user agent in X-Atlas-Client-IP
      # / X-Atlas-Client-User-Agent.
      # Scope: legacy_auth:write. query: dry_run. body requires: token.
      def exchange(source, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/migrations/#{enc(source)}/exchange",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Every migration source: what it exports, whether passwords move (or need lazy migration),
      # its bridge preset and variables, and its lazy-migration preset.
      # Scope: jobs:read. query: limit, starting_after.
      def sources(query = nil)
        request(method: :get, path: "/v1/migrations/sources", query: query)
      end

      # Read the zero-logout bridge settings for +source+ (window, JWT preset / issuer / keys,
      # claims, cookie names) and exchange counts. Never returns a shared secret.
      # Scope: legacy_auth:read.
      def get_bridge(source)
        request(method: :get, path: "/v1/migrations/#{enc(source)}/bridge")
      end

      # Create or update the bridge settings for +source+. Every field is optional and merged onto
      # the stored ones; a preset fills the JWT settings from its variables, explicit fields
      # override it. The keys URL must be public https on a production instance. +better_auth+ takes
      # the Better Auth bridge body (see /v1/migrations/better_auth/bridge).
      # Scope: legacy_auth:write. query: dry_run.
      def set_bridge(source, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/migrations/#{enc(source)}/bridge",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove the bridge settings for +source+ (the bridge is off and any stored secret deleted).
      # Scope: legacy_auth:write. query: dry_run.
      def delete_bridge(source, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/migrations/#{enc(source)}/bridge",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      def imports
        @imports ||= Imports.new(@transport)
      end

      class Imports < Base
        # The instance's import public key (created on first read). Seal the export to it; only this
        # instance can open the bundle. One key serves every source. A key with jobs:write may read
        # it too.
        # Scope: jobs:read.
        def get_public_key(source)
          request(method: :get, path: "/v1/migrations/#{enc(source)}/imports/public_key")
        end

        # Replace the import key. A bundle sealed to the old key no longer finalizes; export again
        # with the new key.
        # Scope: jobs:write. query: dry_run.
        def rotate_public_key(source, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/migrations/#{enc(source)}/imports/public_key/rotate",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Start an import from +source+ (status +uploading+). Then upload the sealed bundle with PUT
        # …/parts/{part} and call …/finalize. Nothing is written to users until apply.
        # Scope: jobs:write. query: dry_run.
        def create(source, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/migrations/#{enc(source)}/imports",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # List the imports from +source+, newest first (cursor pagination).
        # Scope: jobs:read. query: limit, starting_after.
        def list(source, query = nil)
          request(method: :get, path: "/v1/migrations/#{enc(source)}/imports", query: query)
        end

        # Fetch one import: status, the dry-run report, live progress and the apply result.
        # Scope: jobs:read.
        def get(source, id)
          request(method: :get, path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}")
        end

        # Delete an import and its stored bundle. Data it already imported stays. Refused (409)
        # while analyzing or applying.
        # Scope: jobs:write. query: dry_run.
        def delete(source, id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Upload part +part+ (1, 2, …) of the sealed bundle: whole lines, at most 10 MiB, as +{
        # "data": "…" }+ or a text/plain body. Re-sending a part replaces it. Only while
        # +uploading+.
        # Scope: jobs:write. query: dry_run. body requires: data.
        def put_part(source, id, part, body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}/parts/#{enc(part)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Close the upload: every part 1..n present, the bundle sealed to the active import key and
        # in a format +source+ reads (else 400 or status +invalid+). The dry run follows: inline up
        # to 4 MiB (200, +ready+), else in the background (202, +analyzing+; poll GET).
        # Scope: jobs:write. query: dry_run.
        def finalize(source, id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}/finalize",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Run the dry run again, optionally with new options (they replace the stored ones). Reads
        # only.
        # Scope: jobs:write. query: dry_run.
        def dry_run(source, id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}/dry_run",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Import the bundle. Every record is an idempotent upsert keyed by its source id, so
        # applying a failed import again resumes where it stopped. Up to 1,000 remaining records run
        # inline (200), more are queued (202). With conflicts in the dry run, send
        # confirm_conflicts: true.
        # Scope: jobs:write. query: dry_run.
        def apply(source, id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/migrations/#{enc(source)}/imports/#{enc(id)}/apply",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
