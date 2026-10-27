# frozen_string_literal: true

require_relative "attack_protection"

module Atlas
  module Resources
    class AttackProtection
      # Store the Play Integrity response-decryption key (base64 AES-256) for app attestation.
      # Write-only; the public verification key is
      # attackProtection.appAttestation.android.verificationKey.
      # Scope: attack_protection:write. query: dry_run.
      def set_app_attestation_secret(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/attack_protection/app_attestation_secret",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove a stored attestation secret: the Play Integrity decryption key (default) or, with
      # kind=devicecheck, the Apple DeviceCheck key. That platform then refuses every request.
      # Scope: attack_protection:write. query: dry_run, kind.
      def remove_app_attestation_secret(query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/attack_protection/app_attestation_secret",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
