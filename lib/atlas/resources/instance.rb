# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance+ — instance configuration (origins, auth config).
    class Instance < Base
      # Known +settings_link.preset+ values for {#set_cookie_consent}. A
      # response's +preset+ stays a plain String, so a value added later still
      # reads fine.
      COOKIE_CONSENT_PRESETS = %w[cookiemunch cookiebot onetrust custom].freeze

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
      #
      # The setting (also returned by {#set_cookie_consent} and
      # {#delete_cookie_consent}) carries +"settings_link"+: nil when there is
      # no link, else a Hash with +"label"+, +"preset"+ (String or nil),
      # +"attributes"+ (Hash of String => String) and +"rendered_attributes"+
      # (the attributes the rendered link carries: yours plus the preset's
      # trigger).
      def get_cookie_consent
        request(method: :get, path: "/v1/instance/cookie_consent")
      end

      # +PUT /v1/instance/cookie_consent+ — set the cookie-consent script for the hosted pages (replaces the whole setting).
      #
      # @param body [Hash] +script_url+ (https, required), and optional
      #   +script_id+, +site_id+, +blocking_mode+ and +extra_origins+ (https
      #   origins the script loads from; added to the page's CSP), and
      #   +settings_link+: a "Cookie settings" link on the hosted pages, or nil
      #   (nil or omitted = no link). A link is a Hash with +label+ (required,
      #   1-60 chars), optional +preset+ (one of {COOKIE_CONSENT_PRESETS}, or
      #   nil) and optional +attributes+ (Hash of String => String; names
      #   +data-*+, +aria-*+, +id+, +class+ or +href+ (https or a +#fragment+);
      #   at most 10; values up to 200 chars). A link needs a preset or at
      #   least one attribute (400 otherwise).
      #
      #   atlas.instance.set_cookie_consent(
      #     script_url: "https://consent.cookiebot.com/uc.js",
      #     settings_link: { label: "Cookie settings", preset: "cookiebot" }
      #   )
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
