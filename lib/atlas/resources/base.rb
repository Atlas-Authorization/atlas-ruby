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

      # The image content type for PNG / JPEG / GIF / WebP bytes, or nil.
      def self.sniff_image_type(data)
        bytes = data.to_s.b
        return "image/png" if bytes.start_with?("\x89PNG\r\n\x1A\n".b)
        return "image/jpeg" if bytes.start_with?("\xFF\xD8\xFF".b)
        return "image/gif" if bytes.start_with?("GIF87a".b, "GIF89a".b)
        return "image/webp" if bytes.byteslice(0, 4) == "RIFF".b && bytes.byteslice(8, 4) == "WEBP".b

        nil
      end

      private

      # Forward to the transport. Keeps +Transport::OMIT+ as the default body so
      # a method that names no body sends none (no content-type), matching the
      # reference SDKs.
      def request(method:, path:, query: nil, body: Atlas::Transport::OMIT,
                  idempotency_key: nil, raw: false, raw_body: nil, content_type: nil, headers: nil)
        @transport.request(
          method: method, path: path, query: query, body: body,
          idempotency_key: idempotency_key, raw: raw,
          raw_body: raw_body, content_type: content_type, headers: headers
        )
      end

      # Upload image bytes (a design background or logo). The content type is
      # sniffed from the bytes when not given (PNG, JPEG, GIF, WebP).
      def upload_image(path, data, content_type, kind)
        type = content_type || Base.sniff_image_type(data)
        if type.nil?
          raise ArgumentError,
                "Could not tell the image type from its bytes; pass content_type: " \
                "(image/png, image/jpeg, image/gif or image/webp)."
        end

        request(method: :post, path: path, query: { kind: kind }, raw_body: data, content_type: type)
      end

      # Percent-encode a single path segment (an id, slug, provider name).
      def enc(segment)
        URI.encode_www_form_component(segment.to_s)
      end
    end
  end
end
