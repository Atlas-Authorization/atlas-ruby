# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/users+ — the user directory, plus emails, identities, MFA, sessions,
    # OAuth access tokens, and consent grants.
    class Users < Base
      # +GET /v1/users+ — cursor-paginated.
      def list(params = {})
        request(method: :get, path: "/v1/users", query: params)
      end

      def get(id)
        request(method: :get, path: "/v1/users/#{enc(id)}")
      end

      # +notify: false+ (the default) guarantees no email, SMS or push is sent to
      # the user as a consequence of the create.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/users", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/users/#{enc(id)}", body: body)
      end

      # +PUT /v1/users/:id/metadata+ — replaces the named bags wholesale.
      def replace_metadata(id, body)
        request(method: :put, path: "/v1/users/#{enc(id)}/metadata", body: body)
      end

      def ban(id)
        request(method: :post, path: "/v1/users/#{enc(id)}/ban")
      end

      def unban(id)
        request(method: :post, path: "/v1/users/#{enc(id)}/unban")
      end

      def lock(id, body = {})
        request(method: :post, path: "/v1/users/#{enc(id)}/lock", body: body)
      end

      def unlock(id)
        request(method: :post, path: "/v1/users/#{enc(id)}/unlock")
      end

      def delete(id)
        request(method: :delete, path: "/v1/users/#{enc(id)}")
      end

      def reset_mfa(id)
        request(method: :post, path: "/v1/users/#{enc(id)}/reset_mfa")
      end

      def delete_mfa_factor(id, factor_id)
        request(method: :delete, path: "/v1/users/#{enc(id)}/mfa/#{enc(factor_id)}")
      end

      # +GET /v1/users/:id/sessions+ — the user's sessions. Each item carries
      # +last_active_organization_id+ and +impersonated_by+ (String or nil) and
      # +idle_expires_at+ (epoch ms the session ends from inactivity; same value
      # as +abandon_at+).
      def list_sessions(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/sessions")
      end

      def revoke_sessions(id)
        request(method: :post, path: "/v1/users/#{enc(id)}/sessions/revoke")
      end

      def add_email(id, body)
        request(method: :post, path: "/v1/users/#{enc(id)}/email_addresses", body: body)
      end

      def verify_email(id, email_id)
        request(method: :post, path: "/v1/users/#{enc(id)}/email_addresses/#{enc(email_id)}/verify")
      end

      def set_primary_email(id, email_id)
        request(method: :post, path: "/v1/users/#{enc(id)}/email_addresses/#{enc(email_id)}/primary")
      end

      # +GET /v1/users/:id/oauth_access_tokens/:provider+ — a live provider credential.
      def get_oauth_access_token(id, provider)
        request(method: :get, path: "/v1/users/#{enc(id)}/oauth_access_tokens/#{enc(provider)}")
      end

      # +GET /v1/users/:id/identities+ — base Atlas identity + one per linked account.
      def list_identities(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/identities")
      end

      # +POST /v1/users/:id/identities+ — merge a secondary user INTO this one.
      def link_identity(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/identities", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/external_accounts/connect+ — backend-initiated connect flow.
      def connect_external_account(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/external_accounts/connect", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/users/:id/identities/:identity_id+ — extract a linked identity into a new user.
      def unlink_identity(id, identity_id)
        request(method: :delete, path: "/v1/users/#{enc(id)}/identities/#{enc(identity_id)}")
      end

      # +GET /v1/users/:id/grants+ — the OAuth clients this user has authorized.
      def list_grants(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/grants")
      end

      # +DELETE /v1/users/:id/grants+ — revoke every consent grant the user holds.
      def revoke_all_grants(id)
        request(method: :delete, path: "/v1/users/#{enc(id)}/grants")
      end

      # +DELETE /v1/grants/:id+ — revoke ONE consent grant (instance-scoped).
      def revoke_grant(grant_id)
        request(method: :delete, path: "/v1/grants/#{enc(grant_id)}")
      end

      # +POST /v1/users/by_emails+ — resolve a batch of email addresses to user ids. Pass include_unverified: true for rights requests (DSAR), so an unconfirmed address is still found.
      def by_emails(body)
        request(method: :post, path: "/v1/users/by_emails", body: body)
      end

      # +POST /v1/users/:id/approval_requests+ — push a number-matching "approve this action" prompt to the user's registered devices. Show the returned match_number to the user.
      def request_approval(id, body)
        request(method: :post, path: "/v1/users/#{enc(id)}/approval_requests", body: body)
      end

      # +GET /v1/users/:id/approval_requests/:approvalId+ — poll a transaction-approval request: pending, approved, denied or expired.
      def get_approval_request(id, approval_id)
        request(method: :get, path: "/v1/users/#{enc(id)}/approval_requests/#{enc(approval_id)}")
      end

      # +POST /v1/users/:id/consents+ — record a versioned consent grant (or a withdrawal with status: "withdrawn").
      def record_consent(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/consents", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/users/:id/consents+ — the user's recorded consents with their versions and timestamps.
      def list_consents(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/consents")
      end

      # +POST /v1/users/:id/deletion+ — schedule a graceful deletion with a cancellation window (grace_seconds).
      def schedule_deletion(id, body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/deletion", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/deletion/cancel+ — cancel a scheduled deletion inside its grace window.
      def cancel_deletion(id, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/deletion/cancel", idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/deletion/finalize+ — finalize a scheduled deletion whose grace window has lapsed.
      def finalize_deletion(id, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/deletion/finalize", idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/directives+ — impose a directive on a user (suspended_until, read_only, forced_logout, reason).
      def impose_directive(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/directives", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/users/:id/directives+ — lift a previously imposed directive.
      def lift_directive(id)
        request(method: :delete, path: "/v1/users/#{enc(id)}/directives")
      end

      # +POST /v1/users/:id/erasure_acks+ — acknowledge that your app purged its copy of the user's data during a scheduled deletion (optionally contributing a payload to the erasure export).
      def acknowledge_erasure(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/erasure_acks", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/users/:id/erasure_export+ — the erasure export: Atlas's data about the user plus every app's contributed payload.
      def erasure_export(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/erasure_export")
      end

      # +DELETE /v1/users/:id/identities/by-provider/:provider+ — hard-remove a provider identity from a user (undo a mis-import). The account's only sign-in identity is refused.
      def remove_identity_by_provider(id, provider, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/users/#{enc(id)}/identities/by-provider/#{enc(provider)}",
          idempotency_key: idempotency_key
        )
      end

      # +POST /v1/users/:id/identities/import+ — link a known provider identity without an interactive OAuth flow (migrations).
      def import_identity(id, body, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/identities/import",
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # +GET /v1/users/:id/notification_preferences+ — the user's notification preferences, per category.
      def get_notification_preferences(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/notification_preferences")
      end

      # +PATCH /v1/users/:id/notification_preferences+ — change notification preferences: { category => enabled }.
      def update_notification_preferences(id, preferences)
        request(
          method: :patch,
          path: "/v1/users/#{enc(id)}/notification_preferences",
          body: { preferences: preferences }
        )
      end

      # +GET /v1/users/:id/organization_memberships+ — the organizations the user belongs to, with role, plan and join time. Cursor-paginated.
      def list_organization_memberships(id, params = {})
        request(method: :get, path: "/v1/users/#{enc(id)}/organization_memberships", query: params)
      end

      # +DELETE /v1/users/:id/passkeys/:passkeyId+ — remove one of the user's passkeys.
      def delete_passkey(id, passkey_id, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/users/#{enc(id)}/passkeys/#{enc(passkey_id)}",
          idempotency_key: idempotency_key
        )
      end

      # +POST /v1/users/:id/password+ — set (reset) the user's password. Pass sign_out_of_other_sessions: true to end their other sessions.
      def set_password(id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/users/#{enc(id)}/password", body: body, idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/phone_numbers+ — add a phone number (starts unverified).
      def add_phone_number(id, phone_number, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/phone_numbers",
          body: { phone_number: phone_number },
          idempotency_key: idempotency_key
        )
      end

      # +DELETE /v1/users/:id/phone_numbers/:pid+ — remove a phone number from the user.
      def delete_phone_number(id, phone_number_id, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/users/#{enc(id)}/phone_numbers/#{enc(phone_number_id)}",
          idempotency_key: idempotency_key
        )
      end

      # +POST /v1/users/:id/phone_numbers/:pid/verify+ — mark a phone number verified.
      def verify_phone_number(id, phone_number_id, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/phone_numbers/#{enc(phone_number_id)}/verify",
          idempotency_key: idempotency_key
        )
      end

      # +DELETE /v1/users/:id/profile_image+ — clear the user's profile image.
      def delete_profile_image(id, idempotency_key: nil)
        request(method: :delete, path: "/v1/users/#{enc(id)}/profile_image", idempotency_key: idempotency_key)
      end

      # +POST /v1/users/:id/progression/events+ — append an idempotent progression event (XP, level or state) for the user.
      def record_progression_event(id, body, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/users/#{enc(id)}/progression/events",
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # +GET /v1/users/:id/resolved+ — the user as a flat identity: primary email, email_verified, name, image_url and linked provider identities.
      def resolved(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/resolved")
      end

      # +GET /v1/users/:id/sign_in_history+ — the user's successful sign-ins, newest first. Cursor-paginated (limit, starting_after).
      def sign_in_history(id, params = {})
        request(method: :get, path: "/v1/users/#{enc(id)}/sign_in_history", query: params)
      end

      # +GET /v1/users/:id/state+ — the user's portable state: progression, tier, flair, entitlements, directives and roles.
      def state(id)
        request(method: :get, path: "/v1/users/#{enc(id)}/state")
      end
    end
  end
end
