# frozen_string_literal: true

require "securerandom"

module Atlas
  # W3C Trace Context +traceparent+ helpers. Atlas stores an inbound
  # +traceparent+ as the trace of everything the request emits (webhook
  # deliveries, back-channel logouts, referral calls, verify errors) and sends
  # one on every delivery, so one id finds a case across systems.
  #
  #   atlas = Atlas::Client.new(key, traceparent: Atlas::Trace.generate)
  #   atlas.with_options(traceparent: Atlas::Trace.child(inbound_header)).users.get("user_1")
  module Trace
    PATTERN = /\A00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})\z/

    Parsed = Struct.new(:trace_id, :parent_id, :flags, keyword_init: true) do
      def sampled? = (flags.to_i(16) & 1) == 1
    end

    module_function

    # A fresh +traceparent+ value (sampled).
    def generate
      "00-#{SecureRandom.hex(16)}-#{SecureRandom.hex(8)}-01"
    end

    # @return [Atlas::Trace::Parsed, nil] nil when the header is not a valid version-00 +traceparent+
    #   (all-zero ids are invalid).
    def parse(header)
      m = PATTERN.match(header.to_s.strip.downcase)
      return nil if m.nil? || m[1] == "0" * 32 || m[2] == "0" * 16

      Parsed.new(trace_id: m[1], parent_id: m[2], flags: m[3])
    end

    def valid?(header)
      !parse(header).nil?
    end

    # Continue a trace: same trace id, a new span id. A missing or invalid
    # +parent+ starts a new trace.
    def child(parent = nil)
      p = parent && parse(parent)
      return generate if p.nil?

      "00-#{p.trace_id}-#{SecureRandom.hex(8)}-#{p.flags}"
    end

    # The +traceparent+ from a Hash/Rack headers object, if any.
    def from_headers(headers)
      return nil if headers.nil?

      headers.each do |key, value|
        k = key.to_s
        next unless k.casecmp?("traceparent") || k.casecmp?("HTTP_TRACEPARENT")

        value = value.first if value.is_a?(Array)
        return value&.to_s
      end
      nil
    end
  end

  # Atlas key formats. New keys are +atlas_<env>_<kind>_<random>+ (for example
  # +atlas_live_sk_...+); the legacy +sk_+ / +pk_+ / +psk_+ / +whsec_+ prefixes
  # stay valid, so any prefix check must accept both.
  module KeyFormat
    LEGACY_PREFIXES = { "sk_" => :secret, "pk_" => :publishable, "psk_" => :platform, "whsec_" => :webhook_secret }.freeze
    SUITE = /\Aatlas_(?<env>[a-z]+)_(?<kind>[a-z]+)_/

    module_function

    # @return [Symbol, nil] +:secret+, +:publishable+, +:platform+, +:webhook_secret+, +:unknown+ (a
    #   suite key of another kind) or nil when it is not an Atlas key.
    def kind(key)
      key = key.to_s
      m = SUITE.match(key)
      if m
        return { "sk" => :secret, "pk" => :publishable, "psk" => :platform, "whsec" => :webhook_secret }.fetch(m[:kind], :unknown)
      end
      LEGACY_PREFIXES.each { |prefix, kind| return kind if key.start_with?(prefix) }
      nil
    end

    def secret_key?(key) = kind(key) == :secret
    def publishable_key?(key) = kind(key) == :publishable
    def platform_key?(key) = kind(key) == :platform
    def webhook_secret?(key) = kind(key) == :webhook_secret

    # +"live"+, +"test"+ ... for a suite key; +nil+ for a legacy key (read the
    # prefix after it: +sk_live_+ / +sk_test_+) or a non-key.
    def environment(key)
      m = SUITE.match(key.to_s)
      m && m[:env]
    end
  end
end
