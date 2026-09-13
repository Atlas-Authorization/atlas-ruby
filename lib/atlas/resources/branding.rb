# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/branding+ — the hosted-page / email appearance bag.
    class Branding < Base
      def get
        request(method: :get, path: "/v1/branding")
      end

      # A PARTIAL merge — one field changes, the rest is preserved.
      def update(body)
        request(method: :patch, path: "/v1/branding", body: body)
      end

      # Render a draft through the live sign-in renderer without saving it.
      def preview(body)
        request(method: :post, path: "/v1/branding/preview", body: body)
      end
    end
  end
end
