# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/machines+ — machine (M2M) identities, the device registry and enrolment tokens.
    class Machines < Base
      # +POST /v1/machines+ — create a machine identity. The machine secret is returned once.
      def create(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/machines", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/machines+ — machine identities, filterable by status, hostname, owner_user_id, organization_id and metadata.
      def list(params = {})
        request(method: :get, path: "/v1/machines", query: params)
      end

      # +GET /v1/machines/:id+ — one machine identity.
      def get(id)
        request(method: :get, path: "/v1/machines/#{enc(id)}")
      end

      # +PATCH /v1/machines/:id+ — rename a machine.
      def rename(id, name)
        request(method: :patch, path: "/v1/machines/#{enc(id)}", body: { name: name })
      end

      # +PATCH /v1/machines/:id/metadata+ — merge device metadata (hostname, os, app_version, last_seen_at).
      def patch_metadata(id, metadata)
        request(method: :patch, path: "/v1/machines/#{enc(id)}/metadata", body: { metadata: metadata })
      end

      # +DELETE /v1/machines/:id+ — delete a machine identity.
      def delete(id)
        request(method: :delete, path: "/v1/machines/#{enc(id)}")
      end

      # +POST /v1/machines/:id/approve+ — approve a device that enrolled under an approval-gated token.
      def approve(id)
        request(method: :post, path: "/v1/machines/#{enc(id)}/approve")
      end

      # +POST /v1/machines/:id/revoke+ — revoke a machine; it stops minting tokens immediately.
      def revoke(id)
        request(method: :post, path: "/v1/machines/#{enc(id)}/revoke")
      end

      # +POST /v1/machines/:id/rotate_key+ — register a new device public key; the old key stops verifying.
      def rotate_key(id, public_key_pem)
        request(method: :post, path: "/v1/machines/#{enc(id)}/rotate_key", body: { public_key_pem: public_key_pem })
      end

      # +POST /v1/machines/:id/rotate_secret+ — rotate the machine secret; the new one is shown once.
      def rotate_secret(id)
        request(method: :post, path: "/v1/machines/#{enc(id)}/rotate_secret")
      end

      # +GET /v1/machines/:id/organization_memberships+ — the organization the machine belongs to (zero or one entry).
      def organization_memberships(id)
        request(method: :get, path: "/v1/machines/#{enc(id)}/organization_memberships")
      end

      # +POST /v1/machine_enrolment_tokens+ — mint a machine enrolment token. The token secret is returned once.
      def create_enrolment_token(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/machine_enrolment_tokens", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/machine_enrolment_tokens+ — enrolment tokens (never the secret), newest first.
      def list_enrolment_tokens(params = {})
        request(method: :get, path: "/v1/machine_enrolment_tokens", query: params)
      end

      # +DELETE /v1/machine_enrolment_tokens/:id+ — delete an enrolment token; it can no longer enrol devices.
      def delete_enrolment_token(id)
        request(method: :delete, path: "/v1/machine_enrolment_tokens/#{enc(id)}")
      end

      # +POST /v1/m2m_tokens/verify+ — verify a presented machine secret: { valid, machine_id }.
      def verify_token(token)
        request(method: :post, path: "/v1/m2m_tokens/verify", body: { token: token })
      end
    end
  end
end
