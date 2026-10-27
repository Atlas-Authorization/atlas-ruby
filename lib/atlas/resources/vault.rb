# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Vault < Base
      # Store a secret. +key_context+ (1–10 string labels) is mandatory and is authenticated into
      # the encryption: the value can only be opened with the context it was written under. The
      # value (up to 64 KiB) is sealed under a fresh data key wrapped by the instance key, or by
      # your own cloud KMS key when one is configured. 409 when the name is taken.
      # Scope: vault:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/vault/objects",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List vault objects (metadata only, never values), newest first. Filter by +name_prefix+ or
      # by +key_context+ (a JSON object; objects whose context contains every given label).
      # Scope: vault:list. query: name_prefix, key_context, starting_after, limit.
      def list(query = nil)
        request(method: :get, path: "/v1/vault/objects", query: query)
      end

      # Read a vault object's metadata without its value.
      # Scope: vault:list.
      def metadata(id)
        request(method: :get, path: "/v1/vault/objects/#{enc(id)}/metadata")
      end

      # List the versions of a vault object (number, which key protects it, when written) — never
      # values.
      # Scope: vault:list. query: limit, starting_after.
      def versions(id, query = nil)
        request(method: :get, path: "/v1/vault/objects/#{enc(id)}/versions", query: query)
      end

      # Read a vault object with its decrypted value (the current version, or +version+). Every read
      # is audited. 409 if the version's wrapping key provider is no longer configured; 502
      # VAULT_KMS_ERROR when your KMS refuses.
      # Scope: vault:read. query: version.
      def read(id, query = nil)
        request(method: :get, path: "/v1/vault/objects/#{enc(id)}", query: query)
      end

      # Append a new version with a new value. Earlier versions stay readable. Pass +version_check+
      # (the version you last read) for optimistic concurrency: 409 if another update landed since.
      # Scope: vault:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/vault/objects/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a vault object and every version of it. Irreversible.
      # Scope: vault:delete. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/vault/objects/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      def key_provider
        @key_provider ||= KeyProvider.new(@transport)
      end

      class KeyProvider < Base
        # The customer-managed key that wraps new vault data keys. 404 when none is configured (the
        # instance key is used).
        # Scope: vault:manage.
        def get
          request(method: :get, path: "/v1/vault/key_provider")
        end

        # Bring your own key: wrap new vault data keys with your AWS KMS (+config.region+,
        # +config.key_id+; symmetric key), Google Cloud KMS (+config.crypto_key+; symmetric key) or
        # Azure Key Vault (+config.vault_url+, +config.key_name+; RSA key with wrap/unwrap) key.
        # Atlas proves access with a wrap/unwrap round trip before saving (422 or 502 on refusal).
        # Credentials are write-only. Existing versions stay on the key that wrapped them; switching
        # provider type is a 409 while versions remain on the old one.
        # Scope: vault:manage. query: dry_run.
        def set(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/vault/key_provider",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Stop using your own key for new versions. 409 while any version is still wrapped by it.
        # Scope: vault:manage. query: dry_run.
        def remove(query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/vault/key_provider",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
