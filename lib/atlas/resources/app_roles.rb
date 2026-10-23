# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/app_roles+ — instance-wide user roles, not tied to any organization.
    # A user's app roles ride on the session token as +app_roles+ /
    # +app_permissions+; check them offline with {Atlas.has_app_role?} /
    # {Atlas.has_app_permission?}.
    class AppRoles < Base
      def list
        request(method: :get, path: "/v1/app_roles")
      end

      # +{ key:, name:, description:, permissions: [] }+.
      def create(body)
        request(method: :post, path: "/v1/app_roles", body: body)
      end

      # By id or key.
      def get(id)
        request(method: :get, path: "/v1/app_roles/#{enc(id)}")
      end

      def update(id, body)
        request(method: :patch, path: "/v1/app_roles/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/app_roles/#{enc(id)}")
      end

      # The users holding a role. +params+: +limit+, +offset+.
      def list_users(id, params = {})
        request(method: :get, path: "/v1/app_roles/#{enc(id)}/users", query: params.empty? ? nil : params)
      end

      # A user's app roles and effective permissions.
      def get_for_user(user_id)
        request(method: :get, path: "/v1/users/#{enc(user_id)}/app_roles")
      end

      # +{ roles: [...] }+ replaces the set; +{ add: [...], remove: [...] }+ changes it.
      def set_for_user(user_id, body)
        request(method: :post, path: "/v1/users/#{enc(user_id)}/app_roles", body: body)
      end

      def remove_from_user(user_id, role)
        request(method: :delete, path: "/v1/users/#{enc(user_id)}/app_roles/#{enc(role)}")
      end
    end

    # +/v1/oauth_initial_access_tokens+ — tokens that gate OAuth dynamic client
    # registration (RFC 7591 §3) once +oauthProvider.requireInitialAccessToken+ is on.
    class OAuthInitialAccessTokens < Base
      def list
        request(method: :get, path: "/v1/oauth_initial_access_tokens")
      end

      # +{ description:, expires_in_seconds:, max_uses: }+ (all optional). The
      # +token+ is returned exactly once.
      def create(body = {})
        request(method: :post, path: "/v1/oauth_initial_access_tokens", body: body)
      end

      def revoke(id)
        request(method: :delete, path: "/v1/oauth_initial_access_tokens/#{enc(id)}")
      end
    end
  end
end
