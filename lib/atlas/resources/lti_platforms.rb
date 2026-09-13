# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/lti_platforms+ — LTI 1.3 platform (LMS) registrations.
    class LtiPlatforms < Base
      def list
        request(method: :get, path: "/v1/lti_platforms")
      end

      def get(id)
        request(method: :get, path: "/v1/lti_platforms/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/lti_platforms", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/lti_platforms/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/lti_platforms/#{enc(id)}")
      end
    end
  end
end
