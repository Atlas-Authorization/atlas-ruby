# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class MfaFactors < Base
      # Store (write-only, encrypted) the Yubico cloud API secret key (base64, from
      # upgrade.yubico.com/getapikey). The client id is mfa.yubikey.clientId. Used when
      # mfa.yubikey.mode is "cloud".
      # Scope: instance:write. query: dry_run. body requires: secret.
      def set_yubico_secret(body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/instance/yubico_secret",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove the stored Yubico cloud secret. Cloud-mode YubiKey sign-ins then fail until a new one
      # is stored.
      # Scope: instance:write. query: dry_run.
      def remove_yubico_secret(query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/instance/yubico_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Store (write-only, encrypted) the Duo Web SDK / Universal Prompt client secret. The client
      # id (integration key) and API host are mfa.duo.clientId and mfa.duo.apiHost.
      # Scope: instance:write. query: dry_run. body requires: secret.
      def set_duo_secret(body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/instance/duo_secret",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove the stored Duo client secret.
      # Scope: instance:write. query: dry_run.
      def remove_duo_secret(query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/instance/duo_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Store (write-only, encrypted) the shared secret your TLS proxy sends in the
      # mfa.smartCard.secretHeader header, so Atlas believes the certificate headers only from your
      # proxy. Use a random value of at least 24 characters.
      # Scope: instance:write. query: dry_run. body requires: secret.
      def set_smart_card_secret(body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/instance/smart_card_secret",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove the stored proxy secret. Smart card sign-in then refuses every request.
      # Scope: instance:write. query: dry_run.
      def remove_smart_card_secret(query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/instance/smart_card_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Ask Duo whether the configured integration key, stored secret and API host are accepted
      # (Duo's health check). Reports ok and a message; nothing is changed.
      # Scope: instance:read. query: dry_run.
      def duo_health_check(query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/instance/duo_health_check",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Clear a user's security-question answers (and any lockout). They set new ones from their
      # account.
      # Scope: users:write. query: dry_run.
      def reset_security_questions(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/users/#{enc(id)}/security_questions",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      def yubikeys
        @yubikeys ||= Yubikeys.new(@transport)
      end

      def smart_card_mappings
        @smart_card_mappings ||= SmartCardMappings.new(@transport)
      end

      class Yubikeys < Base
        # List the registered self-held YubiKeys (public id, owner, replay counter). The AES keys
        # are never returned.
        # Scope: users:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/yubikeys", query: query)
        end

        # Register a YubiKey's AES key for self-held Yubico OTP (mfa.yubikey.mode "self_held"). The
        # key is stored encrypted and never returned. Give user_id to assign it; otherwise the first
        # user to enrol it with a valid OTP claims it. 409 when the public id is already registered.
        # Scope: users:write. query: dry_run. body requires: public_id, aes_key.
        def register(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/yubikeys",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Remove a registered YubiKey. A factor already enrolled with it stops verifying.
        # Scope: users:write. query: dry_run.
        def remove(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/yubikeys/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class SmartCardMappings < Base
        # List the certificate attributes registered for a user.
        # Scope: users:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/users/#{enc(id)}/smartcard_mappings", query: query)
        end

        # Pre-register the certificate attribute that signs this user in with a smart card: kind
        # fingerprint (SHA-256, 64 hex), serial (hex, plus the issuer DN), san_email, san_upn or
        # subject_cn. A registered mapping only applies while its kind is listed in
        # mfa.smartCard.mappingRules. 409 when the value is already mapped.
        # Scope: users:write. query: dry_run. body requires: kind, value.
        def add(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/users/#{enc(id)}/smartcard_mappings",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Remove a registered certificate mapping.
        # Scope: users:write. query: dry_run.
        def remove(id, mapping_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/users/#{enc(id)}/smartcard_mappings/#{enc(mapping_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
