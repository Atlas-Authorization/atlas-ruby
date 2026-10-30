# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # The data-rights executor protocol (v2): the routes a DSAR orchestrator calls
    # to find a person and carry out a request against their identity data (needs
    # a key with +privacy:execute+; +privacy:grants:revoke+ lets the erasure revoke
    # the Sign in with Atlas grant), plus the instance's own data-rights
    # orchestrator (+instance:read+ / +instance:write+).
    #
    # Request +type+ accepts +access+, +deletion+, +closure+, +restriction+,
    # +rectification+ (and the aliases +export+, +erasure+, +erase+). Pass a W3C
    # +traceparent+ via +headers:+ (or the client's +traceparent:+ option).
    class Privacy < Base
      # +GET /v1/privacy+ — what this executor speaks (public).
      def discover
        request(method: :get, path: "/v1/privacy")
      end

      # +GET /v1/privacy/presets/:id+ — a ready-made orchestrator profile, e.g. +cookiemunch+.
      def preset(id)
        request(method: :get, path: "/v1/privacy/presets/#{enc(id)}")
      end

      # +POST /v1/privacy/lookup+ — find a person: +atlas: { sub: }+ first, then
      # +atlas: { ext: }+, then +emails+.
      def lookup(body)
        request(method: :post, path: "/v1/privacy/lookup", body: body)
      end

      # +POST /v1/privacy/requests+ — open a request (or get the existing one for
      # the same case). Body: +subjectId+, +type+, +caseId+, +executeAfter+, +reason+.
      # The +Idempotency-Key+ must be 16-128 characters.
      def create_request(body, idempotency_key: nil, headers: nil)
        request(method: :post, path: "/v1/privacy/requests", body: body, idempotency_key: idempotency_key, headers: headers)
      end

      def get_request(id)
        request(method: :get, path: "/v1/privacy/requests/#{enc(id)}")
      end

      # Cancel before it runs: nothing is erased, the account stays.
      def cancel_request(id, idempotency_key: nil)
        request(method: :post, path: "/v1/privacy/requests/#{enc(id)}/cancel", idempotency_key: idempotency_key)
      end

      def orchestrator
        @orchestrator ||= Orchestrator.new(@transport)
      end

      def integration
        @integration ||= Integration.new(@transport)
      end

      # +/v1/instance/privacy_integrations+ — the consent manager, orchestrator,
      # completion webhook and executor key in one view: +{ "object" =>
      # "privacy_integration", "preset", "connected", "cookie_consent",
      # "privacy_orchestrator", "dsr_webhook", "executor_key", "warnings" }+.
      class Integration < Base
        def get
          request(method: :get, path: "/v1/instance/privacy_integrations")
        end

        # +POST /v1/instance/privacy_integrations/connect+ — wire all of it in one
        # idempotent call. Body: +preset+ (+cookiemunch+ or +custom+), +site_id+,
        # +api_key+, +partner_link_id+, +completion_webhook_url+, +cookie_consent+
        # (overrides, or +false+ to leave it alone), +orchestrator+ (further
        # fields) and +key+ (+name+, +scopes+ (privacy:* only), +expires_at+,
        # +allowed_ips+, +allowed_origins+). +executor_key.secret+ comes back once;
        # a re-run answers +executor_key.idempotent_replay+.
        def connect(body)
          request(method: :post, path: "/v1/instance/privacy_integrations/connect", body: body)
        end
      end

      # +/v1/instance/privacy_orchestrator+ — where Atlas opens a case when an
      # account deletion is scheduled. Secrets come back once, on the write that minted them.
      class Orchestrator < Base
        def get
          request(method: :get, path: "/v1/instance/privacy_orchestrator")
        end

        # Body: +provider+, +name+, +enabled+, +case_url+, +cancel_url+ (contains +{id}+),
        # +auth_header+, +auth_scheme+ (+bearer+ / +raw+), +api_key+ (write-only),
        # +use_partner_link+, +partner_link_id+ (implies +use_partner_link+), +site_id+ (the
        # orchestrator-side site a case is for), +sign_requests+, +completion_webhook_url+,
        # +open_closure_cases+ and +cancel_deletion_on_sign_in+ (cancel a self-scheduled
        # deletion when the person signs back in during the grace period). Presets may carry
        # a +case_format+.
        def set(body)
          request(method: :put, path: "/v1/instance/privacy_orchestrator", body: body)
        end

        def delete
          request(method: :delete, path: "/v1/instance/privacy_orchestrator")
        end
      end
    end
  end

  # Verification helpers for the data-rights protocol.
  module Privacy
    # Statuses a privacy request moves through.
    STATUSES = %w[pending scheduled processing completed completed_with_retention rejected no_match cancelled].freeze
    CANONICAL_TYPES = %w[access deletion closure restriction rectification].freeze
    # Scopes the executor routes need.
    SCOPE_EXECUTE = "privacy:execute"
    SCOPE_GRANTS_REVOKE = "privacy:grants:revoke"

    module_function

    # Verify a case call Atlas signs when +sign_requests+ is on (and a
    # +privacy_request.updated+ / +.completed+ webhook): +Atlas-Signature+ is an
    # HMAC-SHA256 over +{Atlas-Id}.{Atlas-Timestamp}.{body}+ with the +whsec_+ secret.
    # Returns an {Atlas::Webhook::Result}. +url:+ also checks +v2+ entries.
    def verify_orchestrator_call(body:, headers:, secret:, **opts)
      Atlas::Webhook.verify(body: body, headers: headers, secret: secret, **opts)
    end

    # True when +event+ is a +privacy_request.updated+ / +.completed+ envelope.
    def privacy_event?(event)
      event.is_a?(Hash) && %w[privacy_request.updated privacy_request.completed].include?(event["type"])
    end

    # An +Idempotency-Key+ the executor protocol accepts (16-128 characters).
    def valid_idempotency_key?(key)
      key.is_a?(String) && key.length.between?(16, 128)
    end
  end
end
