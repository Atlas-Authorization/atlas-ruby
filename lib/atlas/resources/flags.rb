# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Flags < Base
      # Assign an organization's entitlements (a plan, a feature list and/or limits, optionally
      # expiring) without a billing subscription. Replaces whatever was assigned or overridden
      # before; an empty body clears it and the organization falls back to its billing plan. Reaches
      # the +pla+, +fea+ and +ent+ session claims on the next token.
      # Scope: billing:write. query: dry_run.
      def assign_organization_entitlements(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/organizations/#{enc(id)}/entitlements",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Create a feature flag: a typed value (+boolean+, +string+, +int+ or +json+) with a
      # +default_value+, an +off_value+ (served while +enabled+ is false; defaults to false for a
      # boolean, else the default) and ordered targeting +rules+ by org, user, plan and percentage.
      # 409 when the key exists.
      # Scope: flags:write. query: dry_run. body requires: key, type, default_value.
      def create(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/feature_flags",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List feature flags ordered by key. +starting_after+ is the key of the last flag of the
      # previous page.
      # Scope: flags:read. query: starting_after, limit.
      def list(query = nil)
        request(method: :get, path: "/v1/feature_flags", query: query)
      end

      # Read one feature flag.
      # Scope: flags:read.
      def retrieve(key)
        request(method: :get, path: "/v1/feature_flags/#{enc(key)}")
      end

      # Change a flag's description, kill switch, default or off value, or replace its rules. The
      # type and key are fixed.
      # Scope: flags:write. query: dry_run.
      def update(key, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/feature_flags/#{enc(key)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a feature flag.
      # Scope: flags:write. query: dry_run.
      def delete(key, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/feature_flags/#{enc(key)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Evaluate every flag (or the listed +keys+) for a subject (+user_id+, +org_id+, +plan+). When
      # +plan+ is omitted it is the organization's (else the user's) resolved plan. Each result
      # carries the +value+ and a +reason+ (+off+, +default+ or +rule:<index>+).
      # Scope: flags:read. query: dry_run.
      def evaluate(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/feature_flags/evaluate",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Assign a user's entitlements the same way as for an organization.
      # Scope: billing:write. query: dry_run.
      def assign_user_entitlements(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/users/#{enc(id)}/entitlements",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
