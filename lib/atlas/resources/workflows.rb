# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Workflows < Base
      # List lifecycle workflows: a trigger (cron, user created, inactive for N days, membership
      # age, trial end, webhook event) plus ordered steps, run by the worker.
      # Scope: actions:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/workflows", query: query)
      end

      # Create a lifecycle workflow. Steps are notify, disable, delete, invite, add_to_org,
      # remove_from_org, add_to_team, remove_from_team, add_to_group, remove_from_group (an instance
      # group by id or slug) and call_action (an Action with the +workflow_step+ trigger, which may
      # be an +http+ Action). Each subject runs once per workflow; the first failing step stops the
      # run.
      # Scope: actions:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/workflows",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one lifecycle workflow.
      # Scope: actions:read.
      def get(id)
        request(method: :get, path: "/v1/workflows/#{enc(id)}")
      end

      # Update a workflow's name, enabled flag, trigger or steps. Changing the trigger resets its
      # cron slot and event cursor.
      # Scope: actions:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/workflows/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a workflow and its run history.
      # Scope: actions:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/workflows/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Check what a workflow would do for a user (+user_id+; none for cron) without changing
      # anything. Every step is validated against live data and reported as +would_run+ or +failed+.
      # Scope: actions:write. query: dry_run.
      def dry_run(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/workflows/#{enc(id)}/dry_run",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Run a workflow now for one user (+user_id+; none for cron), outside its trigger. Returns the
      # finished run.
      # Scope: actions:write. query: dry_run.
      def run(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/workflows/#{enc(id)}/run",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Run history, newest first, dry runs included (+dry_run+).
      # Scope: actions:read. query: limit, starting_after.
      def runs(id, query = nil)
        request(method: :get, path: "/v1/workflows/#{enc(id)}/runs", query: query)
      end
    end
  end
end
