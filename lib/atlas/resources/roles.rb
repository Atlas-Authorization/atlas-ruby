# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/roles+ — instance roles and their permission sets.
    class Roles < Base
      def list
        request(method: :get, path: "/v1/roles")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/roles", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/roles/#{enc(id)}", body: body)
      end

      # Replace a role's permission set wholesale.
      def set_permissions(id, permissions)
        request(method: :put, path: "/v1/roles/#{enc(id)}/permissions", body: { permissions: permissions })
      end

      # Delete a role. Pass +reassign_to:+ to move every member onto another role
      # first (atomic, before the delete) so an in-use role can be retired.
      def delete(id, reassign_to: nil)
        query = reassign_to ? { reassign_to: reassign_to } : nil
        request(method: :delete, path: "/v1/roles/#{enc(id)}", query: query)
      end
    end

    # +/v1/permissions+ — instance permissions.
    class Permissions < Base
      def list
        request(method: :get, path: "/v1/permissions")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/permissions", body: body, idempotency_key: idempotency_key)
      end

      # Relabel a custom permission (name/description only — the key is immutable).
      def update(id, body)
        request(method: :patch, path: "/v1/permissions/#{enc(id)}", body: body)
      end

      # Delete a custom permission. Fails with +role_in_use+ if a role grants it.
      def delete(id)
        request(method: :delete, path: "/v1/permissions/#{enc(id)}")
      end
    end
  end
end
