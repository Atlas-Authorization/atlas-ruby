# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +GET /v1/entitlements+ — the instance's effective entitlements.
    class Entitlements < Base
      def get
        request(method: :get, path: "/v1/entitlements")
      end
    end

    # +/v1/integration-health+ — one health report across the instance's integrations.
    class IntegrationHealth < Base
      def get
        request(method: :get, path: "/v1/integration-health")
      end

      def providers
        request(method: :get, path: "/v1/integration-health/providers")
      end
    end

    # +GET /v1/embed+ (public) and the deprecated +/v1/instance/csp+ alias.
    class Embed < Base
      # +params+: +instance:+ for the tenant variant.
      def get(params = {})
        request(method: :get, path: "/v1/embed", query: params.empty? ? nil : params)
      end

      # The CSP / embed requirements for this key's instance.
      def csp
        request(method: :get, path: "/v1/instance/csp")
      end
    end

    # +GET /v1/openapi/diff+ — what changed in the API since a date.
    class OpenApi < Base
      # +params+: +since:+ (YYYY-MM-DD), +surface:+.
      def diff(params = {})
        request(method: :get, path: "/v1/openapi/diff", query: params)
      end

      # +GET /.well-known/api-catalog+ (RFC 9727).
      def api_catalog
        request(method: :get, path: "/.well-known/api-catalog")
      end
    end

    # +/v1/delivery_health+ — per-target delivery health and alert contacts.
    class DeliveryHealth < Base
      def get(params = {})
        request(method: :get, path: "/v1/delivery_health", query: params.empty? ? nil : params)
      end

      # Who is emailed when a target fails (+nil+ = the account's owners).
      def set_alert_contacts(kind, target_id, alert_contacts)
        request(method: :put, path: "/v1/delivery_health/#{enc(kind)}/#{enc(target_id)}/alert_contacts",
                body: { alert_contacts: alert_contacts })
      end
    end

    # +/v1/meta+ — facts about Atlas itself.
    class Meta < Base
      # +GET /v1/meta/egress_ips+ — the IPs Atlas delivers webhooks from.
      def egress_ips
        request(method: :get, path: "/v1/meta/egress_ips")
      end
    end
  end
end
