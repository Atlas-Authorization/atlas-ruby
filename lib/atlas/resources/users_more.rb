# frozen_string_literal: true

require_relative "users"

module Atlas
  module Resources
    class Users
      # The user change history, newest first: every profile, metadata and status change (ban, lock,
      # directives and their reversal) with who made it, the reason and expiry, and each changed
      # field with its value before and after. A password change and private_metadata values are
      # recorded as redacted (the field name only). Pages with starting_after.
      # Scope: users:read. query: limit, starting_after, action.
      def history(id, query = nil)
        request(method: :get, path: "/v1/users/#{enc(id)}/history", query: query)
      end

      # A user's parental-consent state (not_required for anyone at or above the age of digital
      # consent) and their guardian links, newest first.
      # Scope: users:read.
      def minor_status(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/minor_status")
      end

      # Re-assess a user from their date-of-birth trait now (for users created before age gating was
      # turned on). 400 when compliance.minors is off.
      # Scope: users:write. query: dry_run.
      def assess_minor(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/minor_status/assess",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Mint an email-verification or password-reset link (and code) for a user WITHOUT sending it,
      # for support tools and invite flows that deliver it themselves. type "email_verification"
      # needs an unverified address (default: the primary); the url opens GET
      # /v1/client/email_addresses/verify and the code works wherever the address is verified by
      # code. type "password_reset" needs a verified address and returns the url and/or code the
      # instance's password-reset setting would have mailed, plus the reset attempt_id; redeeming it
      # is the ordinary reset (it still asks for the second factor and sets a new password).
      # Single-use, expires_in_seconds 60 to 86400 (default 3600). Audited as user.link_generated,
      # never with the secret. Treat the response as a credential. → 201.
      # Scope: users:write. query: dry_run. body requires: type.
      def create_link(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/links",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List a user’s device keys (native biometric sign-in). Never returns key material.
      # Scope: users:read. query: limit, starting_after.
      def list_device_keys(id, query = nil)
        request(method: :get, path: "/v1/users/#{enc(id)}/device_keys", query: query)
      end

      # Revoke one of a user’s device keys so that device can no longer sign in. Scoped to the user;
      # the account holder is notified when account-change notices are on.
      # Scope: users:write. query: dry_run.
      def delete_device_key(id, key_id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/users/#{enc(id)}/device_keys/#{enc(key_id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      def required_actions
        @required_actions ||= RequiredActions.new(@transport)
      end

      def notes
        @notes ||= Notes.new(@transport)
      end

      def guardians
        @guardians ||= Guardians.new(@transport)
      end

      def search
        @search ||= Search.new(@transport)
      end

      class RequiredActions < Base
        # Make a user owe an action at their next sign-in, whatever the method: update_password,
        # verify_email, accept_policy, configure_mfa, update_profile, or custom (sent to an https
        # url; the app closes it with DELETE). The sign-in attempt holds at needs_required_action
        # until it is done (configure_mfa alone routes through MFA enrollment; accept_policy is
        # closed once the policy gate passes; verify_email and configure_mfa clear themselves when
        # already true). Re-requesting an open action is a 200 with the same row. Emits
        # user.required_action_requested. → 201.
        # Scope: users:write. query: dry_run. body requires: action.
        def request_action(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/#{enc(id)}/required_actions",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # The actions a user currently owes, oldest first.
        # Scope: users:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/users/#{enc(id)}/required_actions", query: query)
        end

        # Withdraw an owed action. This is also how an application closes a custom action once the
        # user has finished its step. Emits user.required_action_cleared. 404 when it is not open.
        # Scope: users:write. query: dry_run.
        def clear(id, rid, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/users/#{enc(id)}/required_actions/#{enc(rid)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Owe the same action for many users at once: every member of one organization
        # (organization_id) or an explicit user_ids list, at most 5000. Users outside the instance
        # are skipped, and an already-open action counts as already_open. Emits
        # user.required_action_requested per newly opened action.
        # Scope: users:write. query: dry_run. body requires: action.
        def bulk(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/required_actions/bulk",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class Notes < Base
        # The notes on a user: pinned notes first, then newest first.
        # Scope: users:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/users/#{enc(id)}/notes", query: query)
        end

        # Add a note to a user (up to 5000 characters; at most 500 notes per user). The audit log
        # records that a note was added, never its text. → 201.
        # Scope: users:write. query: dry_run. body requires: body.
        def create(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/#{enc(id)}/notes",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Edit a note: its text, its pin, or both.
        # Scope: users:write. query: dry_run.
        def update(id, note_id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/users/#{enc(id)}/notes/#{enc(note_id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete a note from a user. The audit log keeps that it was deleted.
        # Scope: users:write. query: dry_run.
        def delete(id, note_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/users/#{enc(id)}/notes/#{enc(note_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Guardians < Base
        # Ask a parent or guardian to approve a minor's account. Name them by email or by
        # guardian_user_id (their address is used). Returns the pending link with a one-time
        # consent_url that expires after compliance.minors.consentTtlHours. With send_email: true
        # Atlas mails it through the application's own email provider (422 when none is set up);
        # otherwise deliver consent_url yourself. → 201.
        # Scope: users:write. query: dry_run.
        def request_guardian(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/#{enc(id)}/guardians",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Record consent obtained another way (a signed form, a verified call): the link becomes
        # active with consent_method admin and the account is consented. 409 for a revoked link.
        # Scope: users:write. query: dry_run.
        def approve(id, link_id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/#{enc(id)}/guardians/#{enc(link_id)}/approve",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Withdraw a guardian link. When no active guardian is left, the account needs consent
        # again.
        # Scope: users:write. query: dry_run.
        def revoke(id, link_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/users/#{enc(id)}/guardians/#{enc(link_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Search < Base
        # Search users with a boolean filter tree (and/or/not) over profile columns, traits and
        # metadata keys, organization and org role, MFA enrolled/strategy, sign-in strategy, last
        # sign-in country or IP, and date ranges. Sort with order_by; page with starting_after
        # (creation/update order) or offset (last_sign_in_at order). include_total_count adds
        # total_count. Containment tests on public metadata and traits are answered by an index.
        # Same user objects as GET /v1/users.
        # Scope: users:read. query: dry_run.
        def query(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/search",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Export every user a search matches (up to 10,000; x-export-truncated says when more
        # matched) as CSV (default) or NDJSON. fields picks columns: id, primary_email, username,
        # first_name, last_name, external_id, created_at, last_sign_in_at, banned, mfa_enrolled,
        # plus traits.<key> / public_metadata.<path>. CSV cells that start with = + - @ are prefixed
        # with an apostrophe so a spreadsheet never runs them as formulas.
        # Scope: users:read. query: dry_run.
        def export(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/search/export",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        def views
          @views ||= Views.new(@transport)
        end

        class Views < Base
          # The saved user-search views of the instance, by name.
          # Scope: users:read. query: limit, starting_after.
          def list(query = nil)
            request(method: :get, path: "/v1/users/search/views", query: query)
          end

          # Save a named filter (and sort) to re-run. A filter that could never run is refused; a
          # duplicate name is a 400. → 201.
          # Scope: users:write. query: dry_run. body requires: name.
          def create(body, query = nil, idempotency_key: nil)
            request(
              method: :post,
              path: "/v1/users/search/views",
              query: query,
              body: body,
              idempotency_key: idempotency_key
            )
          end

          # Rename a saved view or change its filter or sort.
          # Scope: users:write. query: dry_run.
          def update(id, body, query = nil, idempotency_key: nil)
            request(
              method: :patch,
              path: "/v1/users/search/views/#{enc(id)}",
              query: query,
              body: body,
              idempotency_key: idempotency_key
            )
          end

          # Delete a saved user-search view.
          # Scope: users:write. query: dry_run.
          def delete(id, query = nil, idempotency_key: nil)
            request(
              method: :delete,
              path: "/v1/users/search/views/#{enc(id)}",
              query: query,
              idempotency_key: idempotency_key
            )
          end
        end
      end
    end
  end
end
