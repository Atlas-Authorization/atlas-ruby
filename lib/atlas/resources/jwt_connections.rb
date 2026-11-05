# frozen_string_literal: true

require "uri"
require_relative "base"

module Atlas
  module Resources
    # +/v1/jwt_connections+ — trusted-JWT connections: your system signs a
    # short-lived JWT (asymmetric key, published at +jwks_uri+) and sends the
    # person to the connection's +login_url+ with +?token=<jwt>&redirect_url=<url>+.
    #
    # Body fields: +organization_id+, +status+ (+draft+ | +active+ | +disabled+),
    # +jwks_uri+ (https), +issuer+, +audience+, +email_claim+ (default +email+),
    # +max_age_seconds+ (30-3600, default 300) and +default_role_id+.
    class JwtConnections < Base
      # Where to send the person's browser to sign in with a trusted JWT
      # (+GET /v1/sso/jwt/:connection_id+). +login_url+ is the connection's +login_url+.
      # A URL, not an API call: the token works once, and the 302 carries a one-time
      # ticket that has to reach the browser.
      def self.sign_in_url(login_url, token, redirect_url)
        separator = login_url.include?("?") ? "&" : "?"
        "#{login_url}#{separator}#{URI.encode_www_form(token: token, redirect_url: redirect_url)}"
      end

      def list
        request(method: :get, path: "/v1/jwt_connections")
      end

      def get(id)
        request(method: :get, path: "/v1/jwt_connections/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/jwt_connections", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/jwt_connections/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/jwt_connections/#{enc(id)}")
      end
    end
  end
end
