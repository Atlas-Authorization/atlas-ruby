# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Iga < Base
      def entitlements
        @entitlements ||= Entitlements.new(@transport)
      end

      def requests
        @requests ||= Requests.new(@transport)
      end

      def grants
        @grants ||= Grants.new(@transport)
      end

      def delegations
        @delegations ||= Delegations.new(@transport)
      end

      def sod
        @sod ||= Sod.new(@transport)
      end

      def lifecycle
        @lifecycle ||= Lifecycle.new(@transport)
      end

      def campaigns
        @campaigns ||= Campaigns.new(@transport)
      end

      class Entitlements < Base
        # List the governed entitlement catalog.
        # Scope: iga:read. query: kind, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/iga/entitlements", query: query)
        end

        # Add an entitlement to the catalog: a role, organization membership, group, resource role,
        # installed-app assignment or custom item, with an owner, a risk level and approval rules.
        # The target must exist. 409 for a key already in use.
        # Scope: iga:write. query: dry_run. body requires: key, name, kind, target.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/entitlements",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one entitlement by id or key.
        # Scope: iga:read.
        def get(id)
          request(method: :get, path: "/v1/iga/entitlements/#{enc(id)}")
        end

        # Change an entitlement (its kind cannot change). A change to the approval rules applies to
        # requests filed afterwards.
        # Scope: iga:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/iga/entitlements/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Remove an entitlement. 409 while it still has active grants.
        # Scope: iga:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/iga/entitlements/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Requests < Base
        # List access requests, newest first.
        # Scope: iga:read. query: status, user_id, requester_user_id, entitlement, limit,
        # starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/iga/requests", query: query)
        end

        # File an access request on behalf of a user. It follows the entitlement's approval steps
        # (and any extra step a separation-of-duties rule adds); with no steps it is fulfilled at
        # once. A blocking separation-of-duties conflict, a user who already holds the access, or a
        # pending duplicate is a 409. +duration_seconds+ makes the grant time-bound (default and
        # maximum: the entitlement's limit).
        # Scope: iga:write. query: dry_run. body requires: entitlement, user_id.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/requests",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one request with its steps and the approvals recorded so far.
        # Scope: iga:read.
        def get(id)
          request(method: :get, path: "/v1/iga/requests/#{enc(id)}")
        end

        # Decide the open step. With +approver_user_id+ the decision is recorded as that person (who
        # must be an approver of the step or hold a delegation); without it the call is an
        # administrator override that settles the step. A denial ends the request. 409 when it is no
        # longer pending.
        # Scope: iga:write. query: dry_run. body requires: decision.
        def decide(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/requests/#{enc(id)}/decide",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Cancel a pending request.
        # Scope: iga:write. query: dry_run.
        def cancel(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/requests/#{enc(id)}/cancel",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # The requests waiting on one person's decision, including those delegated to them.
        # Scope: iga:read. query: approver_user_id (required), limit, starting_after.
        def inbox(query = nil)
          request(method: :get, path: "/v1/iga/approvals", query: query)
        end
      end

      class Grants < Base
        # List grants (what each user was given through governance), newest first.
        # Scope: iga:read. query: user_id, entitlement, status, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/iga/grants", query: query)
        end

        # Give a user an entitlement now, without a request. +expires_at+ makes it time-bound. A
        # blocking separation-of-duties rule refuses it; a require-approval rule refuses unless
        # +override_reason+ is given, which records an accepted violation.
        # Scope: iga:write. query: dry_run. body requires: entitlement, user_id.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/grants",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Take the access away and close the grant, including access that existed before governance
        # adopted it (an expiry, by contrast, leaves adopted access in place).
        # Scope: iga:write. query: dry_run.
        def revoke(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/grants/#{enc(id)}/revoke",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class Delegations < Base
        # List approval delegations.
        # Scope: iga:read. query: delegator_user_id, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/iga/delegations", query: query)
        end

        # Let another user decide a person's approvals (and reviews) for a period of up to a year.
        # Scope: iga:write. query: dry_run. body requires: delegator_user_id, delegate_user_id,
        # ends_at.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/delegations",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # End an approval delegation.
        # Scope: iga:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/iga/delegations/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Sod < Base
        # List separation-of-duties rules: pairs of entitlements one person should not hold
        # together.
        # Scope: iga:read. query: limit, starting_after.
        def list_rules(query = nil)
          request(method: :get, path: "/v1/iga/sod_rules", query: query)
        end

        # Create a rule. +mode+ is +block+ (refuse) or +require_approval+ (an extra approval step on
        # a request; +approver+ names who, default the owner).
        # Scope: iga:write. query: dry_run. body requires: name, entitlement_a, entitlement_b.
        def create_rule(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/sod_rules",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Change a separation-of-duties rule.
        # Scope: iga:write. query: dry_run.
        def update_rule(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/iga/sod_rules/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a rule and its recorded violations.
        # Scope: iga:write. query: dry_run.
        def delete_rule(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/iga/sod_rules/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # The violations report: users who hold both sides of a rule (found by a scan, or accepted
        # at request or assignment time).
        # Scope: iga:read. query: status, limit, starting_after.
        def violations(query = nil)
          request(method: :get, path: "/v1/iga/sod_violations", query: query)
        end

        # Check every rule against what people hold right now: record new conflicts and resolve
        # those that cleared.
        # Scope: iga:write. query: dry_run.
        def scan(query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/sod_violations/scan",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Lifecycle < Base
        # List birthright rules.
        # Scope: iga:read. query: limit, starting_after.
        def list_birthright_rules(query = nil)
          request(method: :get, path: "/v1/iga/birthright_rules", query: query)
        end

        # Create a birthright rule: everyone matching +match+ (a group, organization and role, app
        # role or verified email domain; all conditions must hold) holds the listed entitlements.
        # When someone stops matching, the grants the rule gave are revoked unless
        # +revoke_on_unmatch+ is false.
        # Scope: iga:write. query: dry_run. body requires: name, match, entitlement_ids.
        def create_birthright_rule(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/birthright_rules",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Change a birthright rule.
        # Scope: iga:write. query: dry_run.
        def update_birthright_rule(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/iga/birthright_rules/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a birthright rule (grants it already gave stay until revoked).
        # Scope: iga:write. query: dry_run.
        def delete_birthright_rule(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/iga/birthright_rules/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Re-evaluate one user's birthright access now (joiner or mover).
        # Scope: iga:write. query: dry_run.
        def reconcile(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/users/#{enc(id)}/reconcile",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Offboard a leaver: revoke every grant, cancel pending requests and delegations, and with
        # +close_account+ schedule the account closure through the data-rights path (so downstream
        # erasure webhooks and any DSAR orchestrator run as for any deletion). +grace_seconds+ sets
        # the cancellation window.
        # Scope: iga:write. query: dry_run.
        def offboard(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/users/#{enc(id)}/offboard",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Joiner/mover/leaver settings.
        # Scope: iga:read.
        def settings
          request(method: :get, path: "/v1/iga/settings")
        end

        # Turn the joiner/mover/leaver automation on or off and choose what a deactivated account
        # triggers: +revoke+ (end the grants) or +revoke_and_close+ (also schedule the closure after
        # +leaver_close_grace_seconds+).
        # Scope: iga:write. query: dry_run.
        def update_settings(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/iga/settings",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class Campaigns < Base
        # List certification (access review) campaigns.
        # Scope: iga:read. query: status, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/iga/campaigns", query: query)
        end

        # Create a draft campaign scoped to everything, specific entitlements, or the entitlements
        # for an app, role, group or organization, with reviewers (the person's manager, the
        # entitlement owner, or named users), a due date and reminder days. With +auto_revoke+ the
        # access reviewers mark for revocation is removed when the campaign closes.
        # Scope: iga:write. query: dry_run. body requires: name.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/campaigns",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read a campaign with its progress.
        # Scope: iga:read.
        def get(id)
          request(method: :get, path: "/v1/iga/campaigns/#{enc(id)}")
        end

        # Delete a draft or closed campaign.
        # Scope: iga:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/iga/campaigns/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Launch a draft campaign: it adopts access that exists in Atlas but was never granted
        # through governance, freezes the review list and notifies reviewers.
        # Scope: iga:write. query: dry_run.
        def launch(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/campaigns/#{enc(id)}/launch",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Close a campaign and apply its revoke decisions (with +auto_revoke+). Items nobody
        # reviewed are left in place and reported as pending.
        # Scope: iga:write. query: dry_run.
        def close(id, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/campaigns/#{enc(id)}/close",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # The review items of a campaign.
        # Scope: iga:read. query: decision, reviewer_user_id, limit, starting_after.
        def items(id, query = nil)
          request(method: :get, path: "/v1/iga/campaigns/#{enc(id)}/items", query: query)
        end

        # Progress: totals, percent complete, whether it is overdue, and per-reviewer counts.
        # Scope: iga:read.
        def progress(id)
          request(method: :get, path: "/v1/iga/campaigns/#{enc(id)}/progress")
        end

        # The audit evidence for a campaign as JSON, or CSV with +format=csv+. People are identified
        # by id only (an erased user is flagged), free-text comments are never included, and
        # +masked_emails=true+ adds an address reduced to its first letter and domain.
        # Scope: iga:read. query: format, masked_emails.
        def evidence(id, query = nil)
          request(method: :get, path: "/v1/iga/campaigns/#{enc(id)}/evidence", query: query)
        end

        # Certify or revoke one review item. With +reviewer_user_id+ the decision is the reviewer's
        # (they must be allowed to review it, and may not review their own access); without it it is
        # an administrator decision.
        # Scope: iga:write. query: dry_run. body requires: decision.
        def decide(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/iga/campaign_items/#{enc(id)}/decide",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
