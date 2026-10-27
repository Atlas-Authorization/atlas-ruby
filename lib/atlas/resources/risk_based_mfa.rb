# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/risk_based_mfa+ — the adaptive / risk-based MFA engine config.
    class RiskBasedMfa < Base
      def get
        request(method: :get, path: "/v1/risk_based_mfa")
      end

      def update(body)
        request(method: :patch, path: "/v1/risk_based_mfa", body: body)
      end

      # The risk-event timeline, newest first. query: user_id, level, limit,
      # before (ISO timestamp cursor).
      def list_events(query = nil)
        request(method: :get, path: "/v1/risk_events", query: query)
      end

      # Counts per level/action/mode over the last +days+ (1-90, default 7).
      def event_metrics(query = nil)
        request(method: :get, path: "/v1/risk_events/metrics", query: query)
      end

      # Mark a scored sign-in +legit+ or +fraud+ (+verdict+); the weight of each
      # signal that fired moves accordingly.
      def event_feedback(id, verdict)
        request(method: :post, path: "/v1/risk_events/#{enc(id)}/feedback", body: { verdict: verdict })
      end

      # Allow / challenge / block verdict for a sign-up, sign-in or checkout.
      # body: ip (required), user_agent, device_id, email, user_id, org_id, device.
      def fraud_lookup(body)
        request(method: :post, path: "/v1/fraud/lookup", body: body)
      end
    end
  end
end
