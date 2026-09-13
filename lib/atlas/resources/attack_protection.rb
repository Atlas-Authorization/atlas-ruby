# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/attack_protection+ — brute-force, breached-password, and related gates.
    class AttackProtection < Base
      def get
        request(method: :get, path: "/v1/attack_protection")
      end

      def update(body)
        request(method: :patch, path: "/v1/attack_protection", body: body)
      end
    end
  end
end
