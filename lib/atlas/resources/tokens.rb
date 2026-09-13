# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/tokens+ — authoritative online session-token verification (checks the
    # revocation set). The slow path; prefer local {Atlas::Backend#verify}.
    class Tokens < Base
      def verify(body)
        request(method: :post, path: "/v1/tokens/verify", body: body)
      end
    end
  end
end
