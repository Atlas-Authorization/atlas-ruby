# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/partner_platforms+ — this instance as a partner platform of another product:
    # a product that signs its partner deliveries with a published Ed25519 key set. The
    # partner delivers signed consent events to this instance's receiver; registering is
    # done by the partner from {#registration}, and the partner token it hands back is
    # stored once, encrypted, and never returned by any call (only +token_set+ and
    # +token_prefix+).
    class PartnerPlatforms < Base
      # +GET /v1/partner_platforms+ — the configured platforms plus the ready-made +presets+.
      def list
        request(method: :get, path: "/v1/partner_platforms")
      end

      def get(partner)
        request(method: :get, path: "/v1/partner_platforms/#{enc(partner)}")
      end

      # +PUT /v1/partner_platforms/:partner+ — set up or change one (a preset id fills the
      # defaults). Body (all optional): +name+, +platform_id+, +enabled+, +jwks_url+,
      # +signature_header+, +signature_scheme+, +tolerance_seconds+, +allowed_sources+,
      # +record_consents+, +serves_deployment+.
      def set(partner, body = {})
        request(method: :put, path: "/v1/partner_platforms/#{enc(partner)}", body: body)
      end

      def delete(partner)
        request(method: :delete, path: "/v1/partner_platforms/#{enc(partner)}")
      end

      # +GET /v1/partner_platforms/:partner/registration+ — what to send the partner to be
      # registered: receiver URL, signature expectations, where to send it.
      def registration(partner)
        request(method: :get, path: "/v1/partner_platforms/#{enc(partner)}/registration")
      end

      # +POST /v1/partner_platforms/:partner/token+ — store the partner token the partner
      # handed over (once; +rotate: true+ replaces it). Write-only: no response carries it.
      def store_token(partner, token, rotate: nil, api_base_url: nil)
        body = { token: token }
        body[:rotate] = rotate unless rotate.nil?
        body[:api_base_url] = api_base_url unless api_base_url.nil?
        request(method: :post, path: "/v1/partner_platforms/#{enc(partner)}/token", body: body)
      end

      # +GET /v1/partner_platforms/:partner/deliveries+ — recent deliveries and what became of each.
      def deliveries(partner, limit: nil)
        request(method: :get, path: "/v1/partner_platforms/#{enc(partner)}/deliveries",
                query: limit ? { limit: limit } : nil)
      end

      # Keep the token out of logs and +inspect+ output of this object.
      def inspect
        "#<#{self.class.name}>"
      end
    end
  end
end
