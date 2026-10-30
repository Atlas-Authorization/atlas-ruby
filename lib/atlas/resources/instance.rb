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

      # The instance, including +issuer+, +discovery_url+ and +jwks_uri+ (they
      # change when a custom domain goes active, so read them rather than
      # hard-coding them) and +allowed_origin_integrations+ (origin =>
      # +"redirect"+ | +"embedded"+).
      def get
        request(method: :get, path: "/v1/instance")
      end

      # An +allowed_origins+ entry is an origin String, or
      # +{ origin:, integration: }+ where +integration+ is +"redirect"+
      # (hosted-redirect OIDC), +"embedded"+ (the sign-in components run on the
      # origin) or +"auto"+ / +nil+ (clear the hint). +auth_config+ also takes
      # +strictRequestBodies+, +dangerouslyReportSkippedEmailsAsVerified+ and
      # +branding: { audiences: }+.
      #
      #   atlas.instance.update({ allowed_origins: ["https://a.example", { origin: "https://app.example", integration: "redirect" }] })
      #
      # The result may carry +"warnings"+: what the write did not do as sent,
      # each +{ "code", "message", "field", "hint", "did_you_mean", "origin" }+
      # (+code+ +origin_still_referenced+: a removed origin URLs still point at;
      # +unknown_field+: an ignored auth_config key, +field+ its full path).
      def update(body)
        request(method: :patch, path: "/v1/instance", body: body)
      end

      # "Sign in with Atlas" on the instance (+/v1/instance/sign_in_with_atlas+).
      def sign_in_with_atlas
        @sign_in_with_atlas ||= SignInWithAtlas.new(@transport)
      end

      # Where the hosted pages send the browser (+/v1/instance/hosted_pages+).
      def hosted_pages
        @hosted_pages ||= HostedPages.new(@transport)
      end

      # Settings: +{ "object" => "sign_in_with_atlas", "enabled", "connection_id",
      # "managed_via" ("instance_toggle" | "linked" | nil), "connection_status",
      # "available", "issuer", "candidates" => [{ "id", "client_id",
      # "managed_by_this_instance" }] }+.
      class SignInWithAtlas < Base
        def get
          request(method: :get, path: "/v1/instance/sign_in_with_atlas")
        end

        # Body: +enabled+ and optional +connection_id+. +enabled: true+ links an
        # existing connection to the Atlas issuer (or the one named), else creates one.
        def update(body)
          request(method: :patch, path: "/v1/instance/sign_in_with_atlas", body: body)
        end
      end

      # Settings: +{ "object" => "hosted_pages", "sign_in_url", "sign_up_url",
      # "user_url", "hosted" => { "sign_in", "sign_up", "user" } }+. A set URL makes
      # the hosted page answer 302 there.
      class HostedPages < Base
        def get
          request(method: :get, path: "/v1/instance/hosted_pages")
        end

        # Body: +sign_in_url+, +sign_up_url+, +user_url+ (https, on an allowed
        # origin; +nil+ clears one).
        def update(body)
          request(method: :patch, path: "/v1/instance/hosted_pages", body: body)
        end
      end

      # Write +auth_config.accountLinkingTrust+: keys are an exact provider key,
      # a +"prefix*"+ or +"*"+; values +"always"+ (vouch for the provider's
      # email, for linking only), +"verified"+ or +"never"+ (refused with 409
      # +IDENTITY_ALREADY_LINKED+). An account that never proved its email is
      # never linked. See {Atlas::LINKING_TRUST_LEVELS}.
      def set_account_linking_trust(trust)
        update({ auth_config: { accountLinkingTrust: trust } })
      end

      # Merge +auth_config.captcha+: +provider+ (see {Atlas::CAPTCHA_PROVIDERS}),
      # +siteKey+, +widget+, +minScore+, per-flow / per-action overrides and,
      # for Vercel BotID, +attestationUrl+ (https or a root-relative path).
      def set_captcha_config(captcha)
        update({ auth_config: { captcha: captcha } })
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

      # +GET /v1/instance/unknown_fields_report+ — which request-body fields your
      # callers sent that Atlas ignored over the last +days+ (default 7), and
      # whether it is +safe_to_enable_strict+ request bodies.
      def unknown_fields_report(days: nil)
        request(method: :get, path: "/v1/instance/unknown_fields_report", query: days.nil? ? nil : { days: days })
      end

      # +GET /v1/instance/preflight+ with filters: +min_severity+ and
      # +include_suppressed+. The report carries +min_severity+, +suppressed+,
      # +integrations+; findings carry +group+.
      def preflight_filtered(params = {})
        request(method: :get, path: "/v1/instance/preflight", query: params.empty? ? nil : params)
      end

      # +POST /v1/instance/move_origin+ — move every URL that points at one
      # origin to another (a domain move), across the instance, its OAuth
      # clients, webhooks, redirect URLs and Sign in with Atlas apps.
      #
      # @param body [Hash] +from+ and +to+ (+scheme://host[:port]+), optional
      #   +dry_run+ (true writes nothing).
      # @return [Hash] +{ "object" => "origin_move", "from", "to", "dry_run",
      #   "applied", "changes" => [{ "object", "id", "field", "before", "after" }],
      #   "problems" }+. A repeated run returns no changes.
      def move_origin(body)
        request(method: :post, path: "/v1/instance/move_origin", body: body)
      end

      # +GET /v1/instance/connections+ — the instance's links to other platforms
      # and their health (+ok+, +checked_at+, +data+ rows with +kind+, +check+,
      # +ok+, +severity+, +subject+, +fix_hint+, +last_checked_at+, +details+).
      def connections
        request(method: :get, path: "/v1/instance/connections")
      end

      # +GET /v1/instance/integrations/chatly+ — the Chatly connection (enabled: false when none).
      def get_chatly_integration
        request(method: :get, path: "/v1/instance/integrations/chatly")
      end

      # +PUT /v1/instance/integrations/chatly+ — connect a Chatly channel (+{ channel: }+).
      def set_chatly_integration(body)
        request(method: :put, path: "/v1/instance/integrations/chatly", body: body)
      end

      # +DELETE /v1/instance/integrations/chatly+ — remove the Chatly connection.
      def delete_chatly_integration
        request(method: :delete, path: "/v1/instance/integrations/chatly")
      end

      # +GET /v1/instance/integrations/forumulate+ — the Forumulate connection (enabled: false when none).
      def get_forumulate_integration
        request(method: :get, path: "/v1/instance/integrations/forumulate")
      end

      # +PUT /v1/instance/integrations/forumulate+ — connect Forumulate spaces
      # (+org_id+, +spaces+: ids or +{ id:, redeem_url: }+, optional +audience+).
      # Replaces the whole connection.
      def set_forumulate_integration(body)
        request(method: :put, path: "/v1/instance/integrations/forumulate", body: body)
      end

      # +DELETE /v1/instance/integrations/forumulate+ — remove the Forumulate connection.
      def delete_forumulate_integration
        request(method: :delete, path: "/v1/instance/integrations/forumulate")
      end

      # +GET /v1/instance/cookie_consent+ — the cookie-consent script injected into the hosted pages (enabled: false when none).
      #
      # The setting (also returned by {#set_cookie_consent} and
      # {#delete_cookie_consent}) carries +"settings_link"+: nil when there is
      # no link, else a Hash with +"label"+, +"preset"+ (String or nil),
      # +"attributes"+ (Hash of String => String) and +"rendered_attributes"+
      # (the attributes the rendered link carries: yours plus the preset's
      # trigger), +"culture"+ (+"page"+ or +"browser"+) and
      # +"declared_cookies"+: every cookie and browser-storage key Atlas
      # writes for the instance (+name+, +pattern+, +store+, +domain+,
      # +lifetime_seconds+, +lifetime+, +http_only+, +category+, +purpose+,
      # +written_when+, +set_by+), for your cookie policy.
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
      #   least one attribute (400 otherwise). Optional +culture+: +"page"+
      #   (default; the script tag carries the page language) or +"browser"+.
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
