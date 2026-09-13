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
    end
  end
end
