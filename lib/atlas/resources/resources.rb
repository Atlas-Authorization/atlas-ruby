# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class ProtectedResources < Base
      # List resources, optionally filtered by +type+ or +parent_id+.
      # Scope: resources:read. query: type, parent_id, limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/resources", query: query)
      end

      # Create or update one resource by +type+ + +external_id+ (your own id for it). +parent+ is
      # +{id}+ or +{type, external_id}+ of an existing resource, or null; it must match the type’s
      # +parent_type+.
      # Scope: resources:write. query: dry_run.
      def upsert(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/resources",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Discovery sync: upsert up to 500 resources in order (list parents before children).
      # Idempotent; call it whenever your app creates or moves resources.
      # Scope: resources:write. query: dry_run.
      def sync(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/resources/sync",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one resource, with its type and parent.
      # Scope: resources:read.
      def get(id)
        request(method: :get, path: "/v1/resources/#{enc(id)}")
      end

      # Delete a resource and its role assignments. Its children are detached to the root.
      # Scope: resources:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/resources/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Does +subject+ hold +permission+ on +resource+? A user subject also holds the roles of the
      # organizations they belong to, plus any +groups+ ids you pass. The response lists the grants
      # that allow it.
      # Scope: resources:check. query: dry_run.
      def check(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/resource_checks",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Up to 100 resource checks in one call.
      # Scope: resources:check. query: dry_run.
      def check_batch(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/resource_checks/batch",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List the resources of an optional +type+ on which +subject+ holds +permission+, paged with
      # +limit+ and +starting_after+ (the response carries +has_more+ and +next_cursor+).
      # Scope: resources:check. query: dry_run.
      def accessible(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/resource_checks/list",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def types
        @types ||= Types.new(@transport)
      end

      def assignments
        @assignments ||= Assignments.new(@transport)
      end

      class Types < Base
        # List the resource types (roles, permissions, parent type).
        # Scope: resources:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/resource_types", query: query)
        end

        # Define a resource type: a +key+, its +roles+ (each a set of permissions, optionally
        # +includes+ other roles), an optional +parent_type+ resources nest under, and +inherit+
        # (default true) controlling whether assignments on a parent flow down.
        # Scope: resources:write. query: dry_run.
        def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/resource_types",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one resource type.
        # Scope: resources:read.
        def get(key)
          request(method: :get, path: "/v1/resource_types/#{enc(key)}")
        end

        # Change a resource type’s name, roles, parent type or inheritance.
        # Scope: resources:write. query: dry_run.
        def update(key, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/resource_types/#{enc(key)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a resource type together with its resources and their role assignments.
        # Scope: resources:write. query: dry_run.
        def delete(key, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/resource_types/#{enc(key)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Assignments < Base
        # List role assignments, filtered by +resource_id+, +subject_type+ or +subject_id+.
        # Scope: resources:read. query: resource_id, subject_type, subject_id, limit,
        # starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/resource_role_assignments", query: query)
        end

        # Assign a +role+ on a +resource+ to a +subject+ (+{type: user|group|org, id}+). +inherit+
        # (default true) also applies it to the resource’s descendants. Re-assigning the same role
        # updates +inherit+.
        # Scope: resources:write. query: dry_run.
        def assign(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/resource_role_assignments",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Revoke a role assignment.
        # Scope: resources:write. query: dry_run.
        def revoke(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/resource_role_assignments/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
