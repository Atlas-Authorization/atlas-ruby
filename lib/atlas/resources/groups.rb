# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Groups < Base
      # Every instance group with its member count, by slug.
      # Scope: users:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/groups", query: query)
      end

      # Create an instance group. Emits group.created. → 201.
      # Scope: users:write. query: dry_run. body requires: slug, name.
      def create(body, query = nil, idempotency_key: nil)
        request(method: :post, path: "/v1/groups", query: query, body: body, idempotency_key: idempotency_key)
      end

      # One group, by id or slug.
      # Scope: users:read.
      def get(id)
        request(method: :get, path: "/v1/groups/#{enc(id)}")
      end

      # Change a group. Emits group.updated.
      # Scope: users:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/groups/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a group: its memberships go, its children move to the top level. Emits group.deleted.
      # Scope: users:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/groups/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # The members of one group (direct members only), with how each joined (manual, dynamic, sso,
      # rule). Cursor paged by user id.
      # Scope: users:read. query: limit, starting_after.
      def list_members(id, query = nil)
        request(method: :get, path: "/v1/groups/#{enc(id)}/members", query: query)
      end

      # Add up to 500 users by hand. A member who joined by filter, SSO or rule becomes manual, so a
      # re-apply leaves them. Emits group.member_added per new member.
      # Scope: users:write. query: dry_run. body requires: user_ids.
      def add_members(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/groups/#{enc(id)}/members",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove up to 500 users from a group. Emits group.member_removed.
      # Scope: users:write. query: dry_run. body requires: user_ids.
      def remove_members(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/groups/#{enc(id)}/members/remove",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Re-evaluate a dynamic group now: users matching dynamic_filter are added, those who no
      # longer match are removed; manual members are never touched (400 when the group has no
      # dynamic_filter, or the filter matches over 50,000 users).
      # Scope: users:write. query: dry_run.
      def reapply(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/groups/#{enc(id)}/reapply",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # A user's direct groups and how they joined each.
      # Scope: users:read. query: limit, starting_after.
      def for_user(id, query = nil)
        request(method: :get, path: "/v1/users/#{enc(id)}/groups", query: query)
      end

      def rules
        @rules ||= Rules.new(@transport)
      end

      class Rules < Base
        # Group rules, lowest priority number first.
        # Scope: users:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/group_rules", query: query)
        end

        # Create a rule: when a user matches condition, run the actions (add to a group, grant an
        # app role, set a trait). → 201.
        # Scope: users:write. query: dry_run. body requires: name, condition, actions.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/group_rules",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Run every enabled rule in priority order. One result per rule.
        # Scope: users:write. query: dry_run.
        def apply_all(query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/group_rules/apply",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # One group rule, with its condition and actions.
        # Scope: users:read.
        def get(id)
          request(method: :get, path: "/v1/group_rules/#{enc(id)}")
        end

        # Change a group rule, its condition or actions.
        # Scope: users:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/group_rules/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a rule. Memberships it created stay until removed.
        # Scope: users:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/group_rules/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Run one rule against every matching user now. Returns the match count and what changed.
        # Scope: users:write. query: dry_run.
        def apply(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/group_rules/#{enc(id)}/apply",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
