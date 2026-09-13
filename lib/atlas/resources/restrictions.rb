# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Allowlist and blocklist share an identical route shape, so they share a
    # class; only the base path differs. Exposed on the client as
    # +client.allowlist+ and +client.blocklist+.
    class Restriction < Base
      def initialize(transport, path)
        super(transport)
        @path = path
      end

      def list
        request(method: :get, path: @path)
      end

      def add(identifier)
        request(method: :post, path: @path, body: { identifier: identifier })
      end

      def remove(id)
        request(method: :delete, path: "#{@path}/#{enc(id)}")
      end
    end
  end
end
