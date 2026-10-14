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

      # The organization policy keys the API knows about (camelCase, as sent).
      # A key not listed here is still passed through, so a newer server field
      # works without an SDK upgrade.
      ORG_POLICY_FIELDS = %w[
        requireMfa ssoRequired sessionIdleOverrideMs allowedSignInMethods
        ipAllowlist maxSessionAgeSeconds endUserPool entitlementPlan entitlementOverrides
      ].freeze

      # +PATCH /v1/organizations/:id/policy+ — partial merge; an explicit +nil+
      # clears an override.
      #
      # @param body [Hash] any of:
      #   - +requireMfa+ [Boolean] members must use MFA;
      #   - +ssoRequired+ [Boolean] members must sign in with SSO;
      #   - +sessionIdleOverrideMs+ [Integer] idle timeout for members;
      #   - +allowedSignInMethods+ [Array<String>] e.g. +"password"+, +"passkey"+,
      #     +"oauth"+, +"oauth:google"+, +"saml"+, +"magic_link"+;
      #   - +ipAllowlist+ [Array<String>] CIDR ranges allowed to sign in;
      #   - +maxSessionAgeSeconds+ [Integer] absolute session cap (300 to 7776000);
      #   - +endUserPool+ [Hash] +{ enabled:, requireApproval:, allowHostedSignup: }+;
      #   - +entitlementPlan+, +entitlementOverrides+ — retired; only +nil+ (clear)
      #     is accepted. Use {Atlas::Resources::EntitlementOverrides} instead.
      # @return [Hash] +{ "object", "organization_id", "policy" }+.
      #
      #   atlas.organizations.update_policy("org_1", { requireMfa: true, ipAllowlist: ["203.0.113.0/24"] })
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

      # +GET /v1/organizations/:id/settings+ — the organization's settings values (validated against the organization settings schema).
      def get_settings(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/settings")
      end

      # +PUT /v1/organizations/:id/settings+ — replace the organization's settings values.
      def replace_settings(id, values, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/organizations/#{enc(id)}/settings",
          body: { values: values },
          idempotency_key: idempotency_key
        )
      end

      # +PATCH /v1/organizations/:id/settings+ — merge into the organization's settings values: a key set to nil is removed, other keys are set, untouched keys stay.
      def update_settings(id, values, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/organizations/#{enc(id)}/settings",
          body: { values: values },
          idempotency_key: idempotency_key
        )
      end

      # +GET /v1/organizations/:id/design+ — the organization's design override and the result of layering it over the instance design.
      def get_design(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/design")
      end

      # +PUT /v1/organizations/:id/design+ — replace the organization's design override. An empty design removes it.
      def replace_design(id, design)
        request(method: :put, path: "/v1/organizations/#{enc(id)}/design", body: { design: design })
      end

      # +PATCH /v1/organizations/:id/design+ — change part of the organization's design override; nil removes a setting.
      def update_design(id, design)
        request(method: :patch, path: "/v1/organizations/#{enc(id)}/design", body: { design: design })
      end

      # +GET /v1/organizations/:id/branding+ — the organization's hosted-page branding overlay. Unset fields inherit the instance brand.
      def get_branding(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/branding")
      end

      # +PUT /v1/organizations/:id/branding+ — set the organization's branding overlay (partial merge; nil clears a field back to the instance brand).
      def update_branding(id, body)
        request(method: :put, path: "/v1/organizations/#{enc(id)}/branding", body: body)
      end

      def audit_streams
        @audit_streams ||= AuditStreams.new(@transport)
      end

      # +/v1/organizations/:id/audit_streams+ — per-organization audit streaming to a SIEM.
      class AuditStreams < Base
        # +GET /v1/organizations/:id/audit_streams+ — the organization's audit stream destinations (never the signing secret).
        def list(organization_id)
          request(method: :get, path: "/v1/organizations/#{enc(organization_id)}/audit_streams")
        end

        # +POST /v1/organizations/:id/audit_streams+ — register an HTTPS audit stream destination for the organization.
        def create(organization_id, body, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/organizations/#{enc(organization_id)}/audit_streams",
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +DELETE /v1/organizations/:id/audit_streams/:streamId+ — delete an audit stream destination.
        def delete(organization_id, stream_id)
          request(method: :delete, path: "/v1/organizations/#{enc(organization_id)}/audit_streams/#{enc(stream_id)}")
        end
      end

      def end_users
        @end_users ||= EndUsers.new(@transport)
      end

      # +/v1/organizations/:org_id/end_users+ — the organization's end-user (reader) pool.
      class EndUsers < Base
        # +GET /v1/organizations/:orgId/end_users+ — the organization's end-user (reader) pool. Filter with status:. Cursor-paginated.
        def list(organization_id, params = {})
          request(method: :get, path: "/v1/organizations/#{enc(organization_id)}/end_users", query: params)
        end

        # +POST /v1/organizations/:orgId/end_users+ — attach a user to the organization's end-user pool.
        def add(organization_id, body, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/organizations/#{enc(organization_id)}/end_users",
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +PATCH /v1/organizations/:orgId/end_users/:userId+ — approve (active), gate (pending) or block an end user.
        def update(organization_id, user_id, body)
          request(
            method: :patch,
            path: "/v1/organizations/#{enc(organization_id)}/end_users/#{enc(user_id)}",
            body: body
          )
        end

        # +DELETE /v1/organizations/:orgId/end_users/:userId+ — remove an end user from the pool.
        def remove(organization_id, user_id)
          request(method: :delete, path: "/v1/organizations/#{enc(organization_id)}/end_users/#{enc(user_id)}")
        end
      end

      def reader_domain
        @reader_domain ||= ReaderDomain.new(@transport)
      end

      # +/v1/organizations/:org_id/reader_domain+ — hosts whose sign-ups join the reader pool.
      class ReaderDomain < Base
        # +GET /v1/organizations/:orgId/reader_domain+ — the organization's reader domain(s) with DNS and certificate status.
        def list(organization_id)
          request(method: :get, path: "/v1/organizations/#{enc(organization_id)}/reader_domain")
        end

        # +POST /v1/organizations/:orgId/reader_domain+ — bind a host to the organization's reader pool. Returns the CNAME to publish.
        def create(organization_id, host, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/organizations/#{enc(organization_id)}/reader_domain",
            body: { host: host },
            idempotency_key: idempotency_key
          )
        end

        # +DELETE /v1/organizations/:orgId/reader_domain+ — remove the organization's reader domain binding.
        def delete(organization_id)
          request(method: :delete, path: "/v1/organizations/#{enc(organization_id)}/reader_domain")
        end
      end
    end
  end
end
