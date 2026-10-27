# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Marketing < Base
      # The marketing settings: which UTM / ad-click-id parameters the SDK captures onto new users,
      # and the GA4, GTM and Hotjar ids hosted pages load after consent.
      # Scope: marketing:read.
      def get_settings
        request(method: :get, path: "/v1/marketing_settings")
      end

      # Change the marketing settings. +capture.params+ empty means the standard set (utm_source,
      # utm_medium, utm_campaign, utm_term, utm_content, utm_id and the common ad click ids). Hosted
      # pages load a configured script only when the visitor's consent manager grants
      # +scripts.consent_category+ (default analytics); with no consent signal nothing loads.
      # Scope: marketing:write. query: dry_run.
      def update_settings(body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/marketing_settings",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # The lead / subscribe form's submissions, newest first, with the first-touch attribution
      # captured with each. +format=csv+ exports up to 50,000.
      # Scope: marketing:read. query: limit, starting_after, form, format.
      def list_leads(query = nil)
        request(method: :get, path: "/v1/leads", query: query)
      end

      # Delete one captured lead.
      # Scope: marketing:write. query: dry_run.
      def delete_lead(id, query = nil, idempotency_key: nil)
        request(method: :delete, path: "/v1/leads/#{enc(id)}", query: query, idempotency_key: idempotency_key)
      end
    end
  end
end
