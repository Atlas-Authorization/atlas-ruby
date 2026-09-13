# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/organizations+ — orgs plus their memberships, invitations, domains,
    # hierarchy, policy, entitlements, and directory-group role grants.
    class Organizations < Base
      def list(params = {})
        request(method: :get, path: "/v1/organizations", query: params)
      end

      def get(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/organizations", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/organizations/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/organizations/#{enc(id)}")
      end

      # +PUT /v1/organizations/:id/metadata+ — replaces the named bags wholesale.
      def update_metadata(id, body)
        request(method: :put, path: "/v1/organizations/#{enc(id)}/metadata", body: body)
      end

      # +PATCH /v1/organizations/:id/policy+.
      def update_policy(id, body)
        request(method: :patch, path: "/v1/organizations/#{enc(id)}/policy", body: body)
      end

      # +PUT /v1/organizations/:id/parent+ — set (or clear, with nil) the parent.
      def set_parent(id, body)
        request(method: :put, path: "/v1/organizations/#{enc(id)}/parent", body: body)
      end

      # +GET /v1/organizations/:id/hierarchy+ — ancestor chain + direct children.
      def hierarchy(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/hierarchy")
      end

      # +GET /v1/organizations/:id/entitlements+ — the org's active feature set.
      def entitlements(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/entitlements")
      end

      # +organizations.memberships+ — members of an org.
      def memberships
        @memberships ||= Memberships.new(@transport)
      end

      # +organizations.invitations+ — pending org invitations.
      def invitations
        @invitations ||= Invitations.new(@transport)
      end

      # +organizations.domains+ — verified email domains for an org.
      def domains
        @domains ||= Domains.new(@transport)
      end

      # +organizations.group_roles+ — directory-group → role grants.
      def group_roles
        @group_roles ||= GroupRoles.new(@transport)
      end

      # Nested: memberships.
      class Memberships < Base
        def list(org_id)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/memberships")
        end

        def add(org_id, body, idempotency_key: nil)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/memberships", body: body, idempotency_key: idempotency_key)
        end

        def update(org_id, user_id, body)
          request(method: :patch, path: "/v1/organizations/#{enc(org_id)}/memberships/#{enc(user_id)}", body: body)
        end

        def remove(org_id, user_id)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/memberships/#{enc(user_id)}")
        end
      end

      # Nested: invitations.
      class Invitations < Base
        def list(org_id)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/invitations")
        end

        def create(org_id, body, idempotency_key: nil)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/invitations", body: body, idempotency_key: idempotency_key)
        end

        def revoke(org_id, invitation_id)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/invitations/#{enc(invitation_id)}/revoke")
        end
      end

      # Nested: domains.
      class Domains < Base
        def list(org_id)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/domains")
        end

        def create(org_id, body, idempotency_key: nil)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/domains", body: body, idempotency_key: idempotency_key)
        end

        def verify(org_id, domain_id)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/domains/#{enc(domain_id)}/verify")
        end

        def delete(org_id, domain_id)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/domains/#{enc(domain_id)}")
        end
      end

      # Nested: directory-group role grants.
      class GroupRoles < Base
        def grant(org_id, group_id, role_id)
          request(method: :put, path: "/v1/organizations/#{enc(org_id)}/groups/#{enc(group_id)}/roles/#{enc(role_id)}")
        end

        def revoke(org_id, group_id, role_id)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/groups/#{enc(group_id)}/roles/#{enc(role_id)}")
        end
      end
    end
  end
end
