# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class PasskeyApi < Base
      # Start registering a passkey for one of your users. Returns WebAuthn creation options for the
      # browser.
      # Scope: passkey_api:write. query: dry_run. body requires: user_id.
      def registration_init(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/passkey_api/registration/init",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Verify the browser’s attestation and store the passkey for the user. 409 if the credential
      # is already registered; 403 if the authenticator is blocked by the passkey policy.
      # Scope: passkey_api:write. query: dry_run. body requires: user_id, challenge,
      # attestation_object, client_data_json.
      def registration_finalize(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/passkey_api/registration/finalize",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Start a passkey login. With user_id the user’s credentials are listed; without it the login
      # is discoverable and the credential names the user.
      # Scope: passkey_api:write. query: dry_run.
      def login_init(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/passkey_api/login/init",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Verify the browser’s assertion. Returns the user_id the passkey belongs to; your backend
      # then starts its own session. Pass user_id to require that exact user. Challenges are single
      # use.
      # Scope: passkey_api:write. query: dry_run. body requires: handle, challenge, credential_id,
      # authenticator_data, client_data_json, signature.
      def login_finalize(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/passkey_api/login/finalize",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # List the passkeys registered for one of your users.
      # Scope: passkey_api:read. query: limit, starting_after.
      def list(user_id, query = nil)
        request(method: :get, path: "/v1/passkey_api/users/#{enc(user_id)}/passkeys", query: query)
      end

      # Delete one of your user’s passkeys.
      # Scope: passkey_api:write. query: dry_run.
      def delete(user_id, id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/passkey_api/users/#{enc(user_id)}/passkeys/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Passkeys stored through the Passkey API on this instance (the metered quantity).
      # Scope: passkey_api:read.
      def usage
        request(method: :get, path: "/v1/passkey_api/usage")
      end
    end
  end
end
