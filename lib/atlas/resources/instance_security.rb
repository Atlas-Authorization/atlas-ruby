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

      # Store a captcha provider secret: +{ secret:, provider: }+. +provider+ (default:
      # the configured one) lets you store it BEFORE turning captcha on — captcha is
      # bring-your-own-keys, and enabling it without a site key and secret is refused
      # with 422 +CAPTCHA_KEYS_REQUIRED+.
      def set_captcha_secret(body)
        request(method: :put, path: "/v1/instance/captcha_secret", body: body)
      end

      # Remove a captcha secret. Refused with 409 +CAPTCHA_IN_USE+ while a flow uses it
      # (+meta["flows"]+); +force: true+ removes it anyway and turns those flows off
      # (returned as +flows_turned_off+).
      def delete_captcha_secret(provider: nil, force: false)
        query = {}
        query[:provider] = provider if provider
        query[:force] = true if force
        request(method: :delete, path: "/v1/instance/captcha_secret", query: query.empty? ? nil : query)
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
