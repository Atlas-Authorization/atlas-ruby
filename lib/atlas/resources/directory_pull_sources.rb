# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class DirectoryPullSources < Base
      # List HR / directory pull sources, optionally for one organization (organization_id).
      # Credentials are never returned.
      # Scope: directory_pull:read. query: organization_id, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/directory_pull_sources", query: query)
      end

      # Create a pull source for an organization: provider (entra, google_workspace, bamboohr,
      # hibob, personio, csv, rest_json), config, write-only credentials and settings (schedule,
      # role mappings, disable on removal).
      # Scope: directory_pull:write. query: dry_run. body requires: organization_id, name, provider.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/directory_pull_sources",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one pull source.
      # Scope: directory_pull:read.
      def get(id)
        request(method: :get, path: "/v1/directory_pull_sources/#{enc(id)}")
      end

      # Change the source name, status (active or paused), config, credentials, default role or
      # settings. Settings are merged.
      # Scope: directory_pull:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/directory_pull_sources/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a pull source and its run log. Users it created are kept.
      # Scope: directory_pull:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/directory_pull_sources/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Upload the CSV a csv source without a URL reads on its next run (up to 5 MiB).
      # Scope: directory_pull:write. query: dry_run.
      def set_csv(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/directory_pull_sources/#{enc(id)}/csv",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def sync_runs
        @sync_runs ||= SyncRuns.new(@transport)
      end

      class SyncRuns < Base
        # Queue a pull now. One run at a time per source (409 otherwise); the worker executes it.
        # Scope: directory_pull:write. query: dry_run.
        def create(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/directory_pull_sources/#{enc(id)}/sync_runs",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # List the runs of a source with counts of people seen, created, re-roled, disabled and
        # re-enabled.
        # Scope: directory_pull:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/directory_pull_sources/#{enc(id)}/sync_runs", query: query)
        end

        # Read one directory pull run with its counts and error.
        # Scope: directory_pull:read.
        def get(id, run_id)
          request(method: :get, path: "/v1/directory_pull_sources/#{enc(id)}/sync_runs/#{enc(run_id)}")
        end
      end
    end
  end
end
