# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance+ — instance configuration (origins, auth config).
    class Instance < Base
      def get
        request(method: :get, path: "/v1/instance")
      end

      def update(body)
        request(method: :patch, path: "/v1/instance", body: body)
      end

      # +GET /v1/instance/preflight+ — check your setup in one call. Read-only.
      #
      # @return [Hash] +{ "object", "ok", "checked_at", "findings" }+. +ok+ is
      #   true when no finding is an error. Each finding is a Hash with
      #   +"severity"+ (+"error"+, +"warning"+ or +"info"+), +"code"+ (stable,
      #   for branching), +"message"+, +"fix"+ and, when it is about one thing,
      #   +"subject"+, a Hash of strings naming it (e.g. +{ "provider" => "google" }+
      #   or +{ "id" => "...", "client_id" => "..." }+).
      #
      #   report = atlas.instance.preflight
      #   report["findings"].each { |f| warn "#{f['severity']}: #{f['message']} -> #{f['fix']}" } unless report["ok"]
      def preflight
        request(method: :get, path: "/v1/instance/preflight")
      end

      # +GET /v1/instance/cookie_consent+ — the cookie-consent script injected into the hosted pages (enabled: false when none).
      def get_cookie_consent
        request(method: :get, path: "/v1/instance/cookie_consent")
      end

      # +PUT /v1/instance/cookie_consent+ — set the cookie-consent script for the hosted pages (replaces the whole setting).
      #
      # @param body [Hash] +script_url+ (https, required), and optional
      #   +script_id+, +site_id+, +blocking_mode+ and +extra_origins+ (https
      #   origins the script loads from; added to the page's CSP).
      def set_cookie_consent(body)
        request(method: :put, path: "/v1/instance/cookie_consent", body: body)
      end

      # +DELETE /v1/instance/cookie_consent+ — turn the hosted-page cookie-consent script off.
      def delete_cookie_consent
        request(method: :delete, path: "/v1/instance/cookie_consent")
      end
    end
  end
end
