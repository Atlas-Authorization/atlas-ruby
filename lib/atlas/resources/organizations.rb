# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/organizations+ — orgs plus their memberships, invitations, domains,
    # hierarchy, policy, entitlements, and directory-group role grants.
    class Organizations < Base
      # +params+: +limit+, +starting_after+, +external_id+ (your own id for the
      # customer) and a +metadata:+ Hash of public_metadata equality filters
      # (sent as +metadata[key]=value+, ANDed).
      def list(params = {})
        request(method: :get, path: "/v1/organizations", query: Atlas::Resources.metadata_query(params))
      end

      # The organization plus its +sso+ block: +{ "connections" => [{ id, type,
      # status }], "scim_base_url" }+.
      def get(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}")
      end

      # +GET /v1/organizations/by_domain/:domain+ — the organization owning a
      # domain (an email address works too: its domain is used). Verified
      # domains only unless +include_unverified: true+. The answer adds
      # +"domain"+ (+id+, +domain+, +status+, +verified_at+).
      def find_by_domain(domain, include_unverified: false)
        request(method: :get, path: "/v1/organizations/by_domain/#{enc(domain)}",
                query: include_unverified ? { include_unverified: "true" } : nil)
      end

      # +GET /v1/organizations/:id/policy+ — +{ "object", "organization_id", "policy" }+.
      def get_policy(id)
        request(method: :get, path: "/v1/organizations/#{enc(id)}/policy")
      end

      # +body+: +name+, +slug+, and optionally +created_by+ (omit or nil for an
      # organization your backend creates with no members yet), +external_id+
      # (unique per instance; 409 with +param: external_id+ when taken),
      # +public_metadata+, +private_metadata+, +owner_email+ (invites that
      # address with the creator role; the answer carries +owner_invitation+),
      # +role_mappings+ (role key => your product's name for it, echoed as the
      # +org_role_mapped+ token claim) and +max_allowed_memberships+.
      #
      #   atlas.organizations.create({ name: "Acme", slug: "acme", external_id: "cus_42",
      #                                owner_email: "it@acme.example", role_mappings: { "org:admin" => "owner" } })
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/organizations", body: body, idempotency_key: idempotency_key)
      end

      # Also takes +external_id+ and +role_mappings+ (+nil+ clears either).
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

      # +organizations.teams+ — teams inside an organization.
      def teams
        @teams ||= Teams.new(@transport)
      end

      # +organizations.roles+ — the roles an org can assign, and its own custom roles.
      def roles
        @roles ||= Roles.new(@transport)
      end

      # Fetch an organization by slug (case-insensitive).
      def get_by_slug(slug)
        request(method: :get, path: "/v1/organizations/by_slug/#{enc(slug)}")
      end

      # Whether a slug is valid and free: +{ slug:, valid:, available: }+.
      def check_slug(slug)
        request(method: :get, path: "/v1/organizations/check_slug", query: { slug: slug })
      end

      # Nested: teams.
      class Teams < Base
        # +params+: +user_id+ narrows to the teams that user is in.
        def list(org_id, params = {})
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/teams", query: params.empty? ? nil : params)
        end

        def create(org_id, body)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/teams", body: body)
        end

        def get(org_id, team_id)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}")
        end

        def update(org_id, team_id, body)
          request(method: :patch, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}", body: body)
        end

        def delete(org_id, team_id)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}")
        end

        def list_members(org_id, team_id)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}/members")
        end

        def add_member(org_id, team_id, user_id)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}/members",
                  body: { user_id: user_id })
        end

        def remove_member(org_id, team_id, user_id)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/teams/#{enc(team_id)}/members/#{enc(user_id)}")
        end
      end

      # Nested: organization-scoped roles (instance roles plus the org's own).
      class Roles < Base
        # +own: true+ lists only the organization's own custom roles.
        def list(org_id, own: false)
          request(method: :get, path: "/v1/organizations/#{enc(org_id)}/roles", query: own ? { own: "true" } : nil)
        end

        # +{ key:, name:, description:, permissions: [] }+.
        def create(org_id, body)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/roles", body: body)
        end

        def update(org_id, role_id, body)
          request(method: :patch, path: "/v1/organizations/#{enc(org_id)}/roles/#{enc(role_id)}", body: body)
        end

        # +reassign_to:+ (a role key) moves members and pending invitations first;
        # without it a role in use is refused (409 ROLE_IN_USE).
        def delete(org_id, role_id, reassign_to: nil)
          request(method: :delete, path: "/v1/organizations/#{enc(org_id)}/roles/#{enc(role_id)}",
                  query: reassign_to ? { reassign_to: reassign_to } : nil)
        end
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

        # Resend a pending invitation: same id and role, a fresh expiry.
        def resend(org_id, invitation_id)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/invitations/#{enc(invitation_id)}/resend")
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

        # Check now. No +method:+ = the DNS TXT check (no body is sent);
        # +"well_known"+ fetches the file in +verification_methods.well_known+;
        # +"email"+ takes the +code+ from {#send_verification_email}.
        def verify(org_id, domain_id, method: nil, code: nil)
          body = { method: method, code: code }.compact
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/domains/#{enc(domain_id)}/verify",
                  body: body.empty? ? Atlas::Transport::OMIT : body)
        end

        # +POST .../domains/:domain_id/verification_email+ — email a 6-digit code
        # to an administrative mailbox at the domain (+address:+ +"admin"+,
        # +"administrator"+, +"hostmaster"+, +"postmaster"+ or +"webmaster"+),
        # through your own email provider (422 EMAIL_DELIVERY_NOT_CONFIGURED
        # without one). The code lasts 30 minutes. Answers the domain plus +sent_to+.
        def send_verification_email(org_id, domain_id, address: nil)
          request(method: :post, path: "/v1/organizations/#{enc(org_id)}/domains/#{enc(domain_id)}/verification_email",
                  body: address.nil? ? {} : { address: address })
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
