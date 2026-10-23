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

      # +GET /v1/instance/signing_keys+ — the published token-signing keys:
      # +current+ and, inside a rotation's grace window, +previous+ with +retires_at+.
      def list_signing_keys
        request(method: :get, path: "/v1/instance/signing_keys")
      end

      # +POST /v1/instance/signing_keys/rotate+ — +{ alg: "RS256"|"ES256",
      # grace_period_seconds:, emergency: }+ (all optional).
      def rotate_signing_key(body = {})
        request(method: :post, path: "/v1/instance/signing_keys/rotate", body: body)
      end

      # +GET /v1/instance/signing_key_provider+ — the key management service the
      # signing key lives in (+"local"+ when none). Never carries credentials.
      def get_signing_key_provider
        request(method: :get, path: "/v1/instance/signing_key_provider")
      end

      # +PUT /v1/instance/signing_key_provider+ — sign every token with a key in
      # your own KMS: +{ provider: "aws_kms" | "gcp_kms" | "azure_key_vault",
      # config:, credentials:, grace_period_seconds:, emergency: }+.
      #   aws_kms: config +{ region, key_id?, alg? }+, credentials +{ access_key_id, secret_access_key, session_token? }+
      #   gcp_kms: config +{ crypto_key, key_version? }+, credentials +{ service_account_json }+
      #   azure_key_vault: config +{ vault_url, key_name, key_version?, alg? }+, credentials +{ tenant_id, client_id, client_secret }+
      def set_signing_key_provider(body)
        request(method: :put, path: "/v1/instance/signing_key_provider", body: body)
      end

      # +DELETE /v1/instance/signing_key_provider+ — rotate back to a key Atlas
      # holds and forget the KMS credentials (+grace_period_seconds+, +emergency+).
      def remove_signing_key_provider(body = {})
        request(method: :delete, path: "/v1/instance/signing_key_provider", body: body)
      end

      # +PUT /v1/instance/wallet_rpc_secret+ — store (write-only, encrypted) the
      # wallet RPC endpoint for an EIP-155 chain, used by wallet token gating and
      # the Sign in with Ethereum ENS lookup. An empty +url+ removes it.
      def set_wallet_rpc_secret(chain_id:, url:)
        request(method: :put, path: "/v1/instance/wallet_rpc_secret", body: { chain_id: chain_id, url: url })
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

      # +GET /v1/instance/proxy_secret+ — whether a trusted reverse proxy secret is
      # set: +set+, +created_at+, +previous_expires_at+, +secret_header+,
      # +client_ip_header+. Never the secret.
      def get_proxy_secret
        request(method: :get, path: "/v1/instance/proxy_secret")
      end

      # +POST /v1/instance/proxy_secret+ — create, or rotate, the trusted reverse
      # proxy secret. The response carries +secret+ (shown once) and +rotated+. On a
      # rotation the replaced secret keeps working for +overlap_seconds+ (default
      # 86400, +0+ stops it now, at most 604800).
      #
      #   atlas.instance_security.create_proxy_secret({ overlap_seconds: 3600 })
      def create_proxy_secret(body = Atlas::Transport::OMIT)
        request(method: :post, path: "/v1/instance/proxy_secret", body: body)
      end

      # +DELETE /v1/instance/proxy_secret+ — remove the proxy secret: X-Atlas-Client-IP is ignored again.
      def delete_proxy_secret
        request(method: :delete, path: "/v1/instance/proxy_secret")
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
