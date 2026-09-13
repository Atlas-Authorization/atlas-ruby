# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance/security+ — kill switches, IP allowlist, and the write-only
    # provider secrets (captcha, Kerberos, LDAP bind password).
    class InstanceSecurity < Base
      def get
        request(method: :get, path: "/v1/instance/security")
      end

      def update(body)
        request(method: :patch, path: "/v1/instance/security", body: body)
      end

      # Store the captcha provider secret. Refused while the provider is +none+.
      def set_captcha_secret(body)
        request(method: :put, path: "/v1/instance/captcha_secret", body: body)
      end

      def delete_captcha_secret
        request(method: :delete, path: "/v1/instance/captcha_secret")
      end

      # Store the Kerberos/IWA trusted-proxy secret.
      def set_kerberos_secret(body)
        request(method: :put, path: "/v1/instance/kerberos_secret", body: body)
      end

      def delete_kerberos_secret
        request(method: :delete, path: "/v1/instance/kerberos_secret")
      end

      # Store an LDAP connection's service-account bind password.
      def set_ldap_bind_password(connection_id, body)
        request(method: :put, path: "/v1/instance/ldap_connections/#{enc(connection_id)}/bind_password", body: body)
      end

      def delete_ldap_bind_password(connection_id)
        request(method: :delete, path: "/v1/instance/ldap_connections/#{enc(connection_id)}/bind_password")
      end
    end
  end
end
