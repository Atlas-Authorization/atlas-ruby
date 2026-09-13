# frozen_string_literal: true

module Atlas
  module Resources
    # Shared base for every resource namespace. Holds the config-bound transport
    # and forwards +#request+, so each namespace method stays a one-liner naming
    # a verb, a path, and its shapes.
    class Base
      def initialize(transport)
        @transport = transport
      end

      private

      # Forward to the transport. Keeps +Transport::OMIT+ as the default body so
      # a method that names no body sends none (no content-type), matching the
      # reference SDKs.
      def request(method:, path:, query: nil, body: Atlas::Transport::OMIT,
                  idempotency_key: nil, raw: false)
        @transport.request(
          method: method, path: path, query: query, body: body,
          idempotency_key: idempotency_key, raw: raw
        )
      end

      # Percent-encode a single path segment (an id, slug, provider name).
      def enc(segment)
        URI.encode_www_form_component(segment.to_s)
      end
    end
  end
end
