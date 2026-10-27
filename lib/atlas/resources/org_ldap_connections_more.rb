# frozen_string_literal: true

require_relative "org_ldap_connections"

module Atlas
  module Resources
    class OrgLdapConnections
      # Read the directory-sync settings of an organization LDAP / Active Directory connection
      # (schedule, filters, group-to-role mapping, disable-on-removal).
      # Scope: sso_connections:read.
      def get_sync(id)
        request(method: :get, path: "/v1/org_ldap_connections/#{enc(id)}/sync")
      end

      # Set the directory-sync settings. Fields you omit keep their value. Enabling requires an
      # active connection and schedules the first run immediately; disabling clears the schedule.
      # Role mappings are matched in order, by group DN.
      # Scope: sso_connections:write. query: dry_run.
      def set_sync(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/org_ldap_connections/#{enc(id)}/sync",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Which relay agent an organization LDAP connection reaches its directory through, if any.
      # Scope: sso_connections:read.
      def get_relay(id)
        request(method: :get, path: "/v1/org_ldap_connections/#{enc(id)}/relay")
      end

      # Route an LDAP connection through a relay agent (agent_id), or back to a direct connection
      # (null). The agent must be active and allow the LDAP server.
      # Scope: sso_connections:write. query: dry_run.
      def set_relay(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/org_ldap_connections/#{enc(id)}/relay",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def sync_runs
        @sync_runs ||= SyncRuns.new(@transport)
      end

      class SyncRuns < Base
        # Queue a sync run now (202). +full+ (default) lists the whole directory and, when
        # disable-on-removal is on, bans users that left it; +delta+ only reads entries changed
        # since the last successful run. Refused with 409 while another run is queued or running.
        # Scope: sso_connections:write. query: dry_run.
        def create(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/org_ldap_connections/#{enc(id)}/sync_runs",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # The sync run log, newest first, with per-run counts (seen, created, updated, skipped,
        # disabled, role changes, groups, errors) and any failure message.
        # Scope: sso_connections:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/org_ldap_connections/#{enc(id)}/sync_runs", query: query)
        end

        # Read one LDAP directory sync run with its counts and error.
        # Scope: sso_connections:read.
        def get(id, run_id)
          request(method: :get, path: "/v1/org_ldap_connections/#{enc(id)}/sync_runs/#{enc(run_id)}")
        end
      end
    end
  end
end
