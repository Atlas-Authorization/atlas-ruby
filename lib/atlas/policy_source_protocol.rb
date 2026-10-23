# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "securerandom"
require "time"
require "uri"

module Atlas
  # Atlas policy source protocol v1 — helpers for the system that SERVES an
  # Atlas instance's policy documents (a CMS, a docs platform, your own service).
  #
  # * Atlas to you: +GET {endpoint_url}/policies+ (the full feed) and
  #   +GET {endpoint_url}/policies?key=<key>+ (one policy, after your event),
  #   signed with the source's signing secret: +atlas-id+, +atlas-timestamp+
  #   (epoch ms) and +atlas-signature: v1,<base64 HMAC-SHA256>+ over
  #   +"{atlas-id}.{atlas-timestamp}.GET\n{path+query}"+. Check it with
  #   {verify_feed_request}, then answer a feed
  #   (+{ "object" => "policy_list", "policies" => [...] }+).
  # * You to Atlas: +POST {webhook_url}+ (from +atlas.policy_source.get+), a
  #   +policy.published+ / +policy.retired+ event signed with the same secret by
  #   {sign_event}. Atlas then re-fetches that policy; it never stores content
  #   from the event.
  #
  # Matches +verifyPolicyFeedRequest+ / +signPolicySourceEvent+ in +@atlasauth/backend+.
  #
  #   v = Atlas::PolicySourceProtocol.verify_feed_request(
  #     method: request.request_method, path_and_query: request.fullpath, headers: request.headers, secret: secret
  #   )
  #   return head(:unauthorized) unless v.verified?
  #   render json: build_feed(v.key) # one policy when v.key is set
  module PolicySourceProtocol
    VERSION = "2026-10-24"
    VERSION_HEADER = "atlas-policies-version"
    TOLERANCE_MS = 5 * 60_000

    # The outcome of {verify_feed_request}. Never raised: check +verified?+.
    # +reason+ is one of +:wrong_method+, +:missing_headers+, +:malformed_signature+,
    # +:stale_timestamp+, +:signature_mismatch+. +key+ is the +key+ query
    # parameter when Atlas asks for one policy.
    FeedResult = Struct.new(:verified, :reason, :delivery_id, :timestamp, :key, :protocol_version, keyword_init: true) do
      def verified?
        verified == true
      end
    end

    # A signed event: send +body+ byte-for-byte with +headers+ (add +content-type: application/json+).
    SignedEvent = Struct.new(:body, :headers, keyword_init: true)

    module_function

    # Verify Atlas's signed GET of your feed. Pass the request's method, its
    # path AND query exactly as received, and its headers. The +atlas-signature+
    # header may carry several +v1,<base64>+ values; one match is enough. A
    # timestamp more than five minutes from now is refused.
    def verify_feed_request(path_and_query:, headers:, secret:, method: nil, now_ms: nil, tolerance_ms: TOLERANCE_MS)
      return failure(:wrong_method) if method && method.to_s.upcase != "GET"

      id = Webhook.header(headers, "atlas-id")
      ts_raw = Webhook.header(headers, "atlas-timestamp")
      signature = Webhook.header(headers, "atlas-signature")
      return failure(:missing_headers) if [id, ts_raw, signature].any? { |v| v.nil? || v.empty? }

      provided = signature.split.select { |e| e.start_with?("v1,") }.map { |e| decode(e[3..]) }
      return failure(:malformed_signature) if provided.empty?

      timestamp = Float(ts_raw.strip, exception: false)
      now = now_ms || (Time.now.to_f * 1000).to_i
      return failure(:stale_timestamp) if timestamp.nil? || !timestamp.finite? || (now - timestamp).abs > tolerance_ms

      expected = mac(secret, id, ts_raw, "GET\n#{path_and_query}")
      # Compare every entry (no early exit), each in constant time.
      matched = provided.map { |candidate| Webhook.secure_compare(expected, candidate) }.any?
      return failure(:signature_mismatch) unless matched

      FeedResult.new(verified: true, reason: nil, delivery_id: id, timestamp: timestamp.to_i,
                     key: query_key(path_and_query), protocol_version: Webhook.header(headers, VERSION_HEADER))
    end

    # Sign a +policy.published+ / +policy.retired+ event for +POST {webhook_url}+
    # (+atlas-id+, +atlas-timestamp+ in ms, +atlas-signature: v1,<base64
    # HMAC-SHA256 of "{id}.{ts}.{body}">+). +occurred_at+ defaults to now (ISO
    # 8601). Atlas also accepts Standard Webhooks signatures if you prefer a
    # library for that.
    #
    #   signed = Atlas::PolicySourceProtocol.sign_event(
    #     event: { type: "policy.published", key: "tos", version: "2026-10-24" }, secret: secret
    #   )
    #   Net::HTTP.post(URI(webhook_url), signed.body, { "content-type" => "application/json" }.merge(signed.headers))
    def sign_event(event:, secret:, id: nil, timestamp_ms: nil)
      payload = { "occurred_at" => Time.now.utc.iso8601(3) }.merge(event.transform_keys(&:to_s))
      body = JSON.generate(payload)
      id ||= "evt_#{SecureRandom.uuid}"
      ts = (timestamp_ms || (Time.now.to_f * 1000).to_i).to_s
      SignedEvent.new(
        body: body,
        headers: {
          "atlas-id" => id,
          "atlas-timestamp" => ts,
          "atlas-signature" => "v1,#{Base64.strict_encode64(mac(secret, id, ts, body))}"
        }
      )
    end

    def mac(secret, id, timestamp, payload)
      OpenSSL::HMAC.digest("SHA256", secret, "#{id}.#{timestamp}.#{payload}")
    end

    def decode(value)
      Base64.decode64(value)
    end

    def query_key(path_and_query)
      q = path_and_query.index("?")
      return nil if q.nil?

      pair = URI.decode_www_form(path_and_query[(q + 1)..]).find { |k, _| k == "key" }
      pair&.last
    rescue ArgumentError
      nil
    end

    def failure(reason)
      FeedResult.new(verified: false, reason: reason)
    end
    private_class_method :mac, :decode, :query_key, :failure
  end
end
