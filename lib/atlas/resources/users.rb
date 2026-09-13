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
    end
  end
end
