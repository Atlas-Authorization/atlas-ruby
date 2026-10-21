# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

module Atlas
  # Verify an inbound Atlas webhook, for the customer consuming events.
  #
  # Atlas signs every delivery: +atlas-signature: v1,<base64>+ is HMAC-SHA256
  # over +"<id>.<timestamp>.<raw body>"+ keyed with the endpoint secret
  # (+whsec_...+), sent with +atlas-id+ and +atlas-timestamp+ (epoch ms). A
  # delivery more than five minutes from now, in either direction, is refused.
  # Verify the RAW body, before any JSON parse. Matches +verifyWebhook+ in
  # +@atlasauth/backend+.
  #
  #   result = Atlas::Webhook.verify(body: request.raw_post, headers: request.headers, secret: secret)
  #   return head(:bad_request) unless result.verified?
  #   return head(:ok) if seen?(result.delivery_id) # a retry already handled
  #   handle(result.event)
  module Webhook
    REPLAY_TOLERANCE_MS = 5 * 60_000

    # The outcome of {Webhook.verify}. Never raised: check +verified?+.
    # +delivery_id+ (the signed +atlas-id+, the same on every retry of one
    # event: deduplicate on it) and +timestamp+ (epoch ms) are set only when
    # verified. +reason+ is one of +:missing_headers+, +:malformed_signature+,
    # +:stale_timestamp+, +:signature_mismatch+.
    Result = Struct.new(:verified, :reason, :event, :delivery_id, :timestamp, keyword_init: true) do
      def verified?
        verified == true
      end
    end

    module_function

    def verify(body:, headers:, secret:, now_ms: nil, tolerance_ms: REPLAY_TOLERANCE_MS)
      raw = body.to_s
      id = header(headers, "atlas-id")
      ts_raw = header(headers, "atlas-timestamp")
      signature = header(headers, "atlas-signature")
      return failure(:missing_headers) if blank?(id) || blank?(ts_raw) || blank?(signature)

      provided = signatures(signature)
      return failure(:malformed_signature) if provided.empty?

      timestamp = Integer(ts_raw.strip, 10) rescue nil
      return failure(:stale_timestamp) if timestamp.nil?

      now = now_ms || (Time.now.to_f * 1000).to_i
      return failure(:stale_timestamp) if (now - timestamp).abs > tolerance_ms

      mac = OpenSSL::HMAC.digest("SHA256", secret, "#{id}.#{timestamp}.#{raw}")
      expected = Base64.strict_encode64(mac)
      # Compare every entry (no early exit), each in constant time.
      matched = provided.map { |candidate| secure_compare(expected, candidate) }.any?
      return failure(:signature_mismatch) unless matched

      event = begin
        parsed = JSON.parse(raw)
        parsed.is_a?(Hash) ? parsed : nil
      rescue JSON::ParserError
        nil
      end
      Result.new(verified: true, reason: nil, event: event, delivery_id: id, timestamp: timestamp)
    end

    # The +v1+ signatures in an +atlas-signature+ header: one +v1,<base64>+
    # entry, or several separated by spaces (while an endpoint secret rotates,
    # Atlas signs with the old and the new secret). Other versions are skipped.
    def signatures(header)
      header.split.filter_map do |entry|
        version, value = entry.split(",", 2)
        value if version == "v1" && !blank?(value)
      end
    end

    def failure(reason)
      Result.new(verified: false, reason: reason)
    end

    def blank?(value)
      value.nil? || value.to_s.empty?
    end

    # Case-insensitive lookup over a Hash or a Rack/Rails headers object
    # (+HTTP_ATLAS_ID+ style keys included).
    def header(headers, name)
      return nil if headers.nil?

      rack = "HTTP_#{name.upcase.tr('-', '_')}"
      headers.each do |key, value|
        k = key.to_s
        next unless k.casecmp?(name) || k.casecmp?(rack)

        value = value.first if value.is_a?(Array)
        return value&.to_s
      end
      nil
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end
