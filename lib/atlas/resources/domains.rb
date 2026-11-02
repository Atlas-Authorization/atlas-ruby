# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/domains+ — custom FAPI/accounts domains and their DNS verification.
    class Domains < Base
      def list
        request(method: :get, path: "/v1/domains")
      end

      # +body+: +{ host:, role:, dns: }+ for a CNAME domain, or a path mount on a
      # host you already run (no DNS): +{ method: "path", hostname:, base_path: }+
      # (+base_path+ defaults to +/__atlas+). A path mount answers +verification+
      # (+url+ and +content+ of the https file to publish), +frontend_api_url+,
      # and +cname_target+ nil.
      #
      #   atlas.domains.create({ method: "path", hostname: "app.example.com", base_path: "/__atlas" })
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/domains", body: body, idempotency_key: idempotency_key)
      end

      # Answers the domain plus +verified+. A verified path mount adds +issuer+
      # (+https://<host><base_path>+), +routing+ (+atlas_ingress+ or
      # +customer_proxy+) and +instructions+ (the reverse-proxy rule). Keep the
      # old issuer accepted for a while with +previous_issuers:+ on {Atlas::Backend}.
      def verify(id)
        request(method: :post, path: "/v1/domains/#{enc(id)}/verify")
      end

      def delete(id)
        request(method: :delete, path: "/v1/domains/#{enc(id)}")
      end
    end
  end
end
