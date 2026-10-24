# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Status feed: +GET /v1/status+ (components with +group+ / +regions+, plus
    # +regions+, +groups+, +incidents+), the instance's status subscription,
    # incidents and upstream status dependencies. Webhook events:
    # +status.incident.created+ / +.updated+ / +.resolved+.
    class Status < Base
      # +GET /v1/status+ — Statuspage-compatible. +region:+ narrows it.
      def get(params = {})
        request(method: :get, path: "/v1/status", query: params.empty? ? nil : params)
      end

      def subscription
        @subscription ||= Subscription.new(@transport)
      end

      def dependencies
        @dependencies ||= Dependencies.new(@transport)
      end

      # +GET /v1/instance/status_incidents+ — +open:+, +limit:+.
      def incidents(params = {})
        request(method: :get, path: "/v1/instance/status_incidents", query: params.empty? ? nil : params)
      end

      class Subscription < Base
        def get
          request(method: :get, path: "/v1/instance/status_subscription")
        end

        def set(body)
          request(method: :put, path: "/v1/instance/status_subscription", body: body)
        end

        def delete
          request(method: :delete, path: "/v1/instance/status_subscription")
        end

        def rotate_feed
          request(method: :post, path: "/v1/instance/status_subscription/rotate_feed")
        end
      end

      class Dependencies < Base
        def list
          request(method: :get, path: "/v1/instance/status_dependencies")
        end

        def create(body, idempotency_key: nil)
          request(method: :post, path: "/v1/instance/status_dependencies", body: body, idempotency_key: idempotency_key)
        end

        def get(id)
          request(method: :get, path: "/v1/instance/status_dependencies/#{enc(id)}")
        end

        def update(id, body)
          request(method: :patch, path: "/v1/instance/status_dependencies/#{enc(id)}", body: body)
        end

        def delete(id)
          request(method: :delete, path: "/v1/instance/status_dependencies/#{enc(id)}")
        end

        def refresh(id)
          request(method: :post, path: "/v1/instance/status_dependencies/#{enc(id)}/refresh")
        end
      end
    end
  end
end
