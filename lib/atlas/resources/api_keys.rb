# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/api_keys+ — end-user API keys a tenant mints for its own subjects.
    class ApiKeys < Base
      # Optionally narrowed to one subject via +subject_type+/+subject_id+.
      def list(query = nil)
        request(method: :get, path: "/v1/api_keys", query: query)
      end

      # Mint a key. The secret is returned once, here. Pass +limits+ (an array of
      # +{ unit:, amount:, period: "request" | "day" | "month" | "total" }+) to set
      # per-key spend caps, metered with #record_usage.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/api_keys", body: body, idempotency_key: idempotency_key)
      end

      # Check a presented secret. Rate-limited — it is an online credential check.
      # A valid result carries the subject, +name+, +claims+, +scopes+,
      # +constraints+, +limits+ and the caps' current-window +usage+.
      def verify(secret)
        request(method: :post, path: "/v1/api_keys/verify", body: { secret: secret })
      end

      def get(id)
        request(method: :get, path: "/v1/api_keys/#{enc(id)}")
      end

      # Change a key's name, claims, scopes, constraints, expiry or +limits+
      # (+nil+ clears the caps).
      def update(id, body)
        request(method: :patch, path: "/v1/api_keys/#{enc(id)}", body: body)
      end

      # Revoke a key. It stays queryable but never authenticates again.
      def delete(id)
        request(method: :delete, path: "/v1/api_keys/#{enc(id)}")
      end

      # +GET /v1/api_keys/revoked+ — keys revoked since a cursor (since:), for deny-listing revoked key ids.
      def list_revoked(params = {})
        request(method: :get, path: "/v1/api_keys/revoked", query: params)
      end

      # +POST /v1/api_keys/:id/usage+ — meter usage against the key's spend caps,
      # atomically. When the debit fits every cap it is recorded and +allowed+ is
      # true; when it would exceed a cap nothing is recorded and the result is
      # +allowed: false+ with +code: "LIMIT_EXCEEDED"+ (a 200, not an error).
      # +idempotency_key+ is sent in the body: the same key returns the first
      # outcome without counting again (+idempotent_replay: true+); reusing it with
      # a different unit or amount raises a 409 +IDEMPOTENCY_CONFLICT+.
      # Returns an +api_key_usage_debit+.
      def record_usage(id, amount:, unit:, idempotency_key: nil)
        body = { amount: amount, unit: unit }
        body[:idempotency_key] = idempotency_key unless idempotency_key.nil?
        request(method: :post, path: "/v1/api_keys/#{enc(id)}/usage", body: body)
      end

      # +GET /v1/api_keys/:id/usage+ — each cap with used/remaining/resets_at, plus
      # the day, month and total counters of every unit debited. Returns an
      # +api_key_usage+.
      def get_usage(id)
        request(method: :get, path: "/v1/api_keys/#{enc(id)}/usage")
      end

      # +POST /v1/api_keys/token+ — mint a short-lived access JWT for an API key (secret, ttl_seconds, audience).
      def mint_token(body)
        request(method: :post, path: "/v1/api_keys/token", body: body)
      end
    end
  end
end
