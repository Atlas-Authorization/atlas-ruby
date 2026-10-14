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

      # Mint a key. The secret is returned once, here.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/api_keys", body: body, idempotency_key: idempotency_key)
      end

      # Check a presented secret. Rate-limited — it is an online credential check.
      def verify(secret)
        request(method: :post, path: "/v1/api_keys/verify", body: { secret: secret })
      end

      def get(id)
        request(method: :get, path: "/v1/api_keys/#{enc(id)}")
      end

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

      # +POST /v1/api_keys/token+ — mint a short-lived access JWT for an API key (secret, ttl_seconds, audience).
      def mint_token(body)
        request(method: :post, path: "/v1/api_keys/token", body: body)
      end
    end
  end
end
