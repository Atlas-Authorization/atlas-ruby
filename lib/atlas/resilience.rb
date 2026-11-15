# frozen_string_literal: true

require "net/http"
require "openssl"
require "socket"
require "time"
require "timeout"

module Atlas
  # Opt-in retries for the Backend API client, aware of how Atlas signals trouble.
  #
  #   Atlas::Client.new(key, retry_policy: Atlas::RetryPolicy.new(max_retries: 3, status_aware: true))
  #   Atlas::Client.new(key, retry_policy: 2)    # two retries with the defaults
  #
  # It retries 429, 502, 503 and 504 answers and network errors, but only requests that are safe to repeat
  # (GET, PUT, DELETE, and POST / PATCH that carry an idempotency key). The wait honours +Retry-After+
  # (seconds or an HTTP date, capped at +max_delay+); without one it backs off exponentially with jitter.
  # With +status_aware+, a 5xx while +GET /v1/status+ declares a major outage (top level, or the +backend_api+
  # component) is not retried: the error comes back at once instead of hammering a service that is down.
  class RetryPolicy
    RETRY_STATUSES = [429, 502, 503, 504].freeze
    NETWORK_ERRORS = [IOError, SystemCallError, SocketError, Timeout::Error, OpenSSL::SSL::SSLError, Net::OpenTimeout, Net::ReadTimeout, EOFError].freeze

    attr_reader :max_retries, :status_aware

    # @param max_retries [Integer] retries after the first attempt.
    # @param base_delay [Numeric] seconds before the first retry (doubles each time).
    # @param max_delay [Numeric] longest wait, including a +Retry-After+.
    # @param status_aware [Boolean] consult the status endpoint before retrying a 5xx.
    # @param sleeper [#call, nil] replaces +sleep+ (tests).
    # @param random [#call, nil] returns a Float in [0, 1) for jitter (tests).
    def initialize(max_retries: 2, base_delay: 0.5, max_delay: 30, status_aware: false, sleeper: nil, random: nil)
      @max_retries = max_retries
      @base_delay = base_delay
      @max_delay = max_delay
      @status_aware = status_aware
      @sleeper = sleeper
      @random = random
    end

    def self.coerce(value)
      case value
      when nil, false then nil
      when RetryPolicy then value
      when Integer then new(max_retries: value)
      when Hash then new(**value.transform_keys(&:to_sym))
      else raise ArgumentError, "retry_policy must be an Atlas::RetryPolicy, a Hash or a retry count."
      end
    end

    def retry_status?(status) = RETRY_STATUSES.include?(status)
    def retry_error?(error) = NETWORK_ERRORS.any? { |k| error.is_a?(k) }

    # Seconds to wait before retry number +attempt+ (0-based); +retry_after+ is the raw header value.
    def delay(attempt, retry_after)
      wanted = parse_retry_after(retry_after)
      return [wanted, @max_delay].min if wanted

      jitter = (@random ? @random.call : rand)
      [(@base_delay * (2**attempt)) * (0.5 + (jitter / 2)), @max_delay].min
    end

    def pause(seconds)
      @sleeper ? @sleeper.call(seconds) : sleep(seconds)
    end

    private

    def parse_retry_after(value)
      return nil if value.nil? || value.to_s.strip.empty?

      v = value.to_s.strip
      return v.to_f if v.match?(/\A\d+(\.\d+)?\z/)

      [Time.httpdate(v) - Time.now, 0].max
    rescue ArgumentError
      nil
    end
  end
end
