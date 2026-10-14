# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/redirect_urls+ — the redirect URL allowlist.
    class RedirectUrls < Base
      # +GET /v1/redirect_urls+ — the allowlisted redirect URLs.
      def list
        request(method: :get, path: "/v1/redirect_urls")
      end

      # +POST /v1/redirect_urls+ — allow a redirect URL (idempotent on the URL).
      def create(url)
        request(method: :post, path: "/v1/redirect_urls", body: { url: url })
      end

      # +GET /v1/redirect_urls/:id+ — one allowlisted redirect URL.
      def get(id)
        request(method: :get, path: "/v1/redirect_urls/#{enc(id)}")
      end

      # +DELETE /v1/redirect_urls/:id+ — remove a redirect URL from the allowlist.
      def delete(id)
        request(method: :delete, path: "/v1/redirect_urls/#{enc(id)}")
      end
    end
  end
end
