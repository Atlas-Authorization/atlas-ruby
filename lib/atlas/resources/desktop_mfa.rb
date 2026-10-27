# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class DesktopMfa < Base
      # The desktop-login MFA policy: who must pass a second factor at OS login, the allowed factors
      # and the offline grace window.
      # Scope: desktop_mfa:read.
      def get_policy
        request(method: :get, path: "/v1/desktop_mfa/policy")
      end

      # Change the desktop-login MFA policy. Send only the fields to change. +applies_to:
      # "selected"+ needs at least one user or organization while enabled.
      # Scope: desktop_mfa:write. query: dry_run.
      def update_policy(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/desktop_mfa/policy",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Issue a single-use code a user types into the workstation agent to enrol it. Valid for
      # +expires_in_minutes+ (default 60, at most 7 days). Shown once.
      # Scope: desktop_mfa:write. query: dry_run.
      def create_enrolment_code(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/desktop_mfa/enrolment_codes",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List enrolled workstations, optionally for one +user_id+.
      # Scope: desktop_mfa:read. query: user_id, limit, starting_after.
      def list_devices(query = nil)
        request(method: :get, path: "/v1/desktop_mfa/devices", query: query)
      end

      # Read one workstation with the offline verifiers issued to it.
      # Scope: desktop_mfa:read.
      def get_device(id)
        request(method: :get, path: "/v1/desktop_mfa/devices/#{enc(id)}")
      end

      # Delete a workstation and its device key.
      # Scope: desktop_mfa:write. query: dry_run.
      def delete_device(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/desktop_mfa/devices/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Revoke a workstation. Its next call is refused with +device_status: revoked+ and it wipes
      # its offline cache; offline unlock stops working at the latest when the cached verifier
      # expires.
      # Scope: desktop_mfa:write. query: dry_run.
      def revoke_device(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/desktop_mfa/devices/#{enc(id)}/revoke",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Void every offline verifier issued to the workstation without revoking it. It receives a
      # fresh one on its next sync.
      # Scope: desktop_mfa:write. query: dry_run.
      def revoke_offline_cache(id, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/desktop_mfa/devices/#{enc(id)}/revoke_offline_cache",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
