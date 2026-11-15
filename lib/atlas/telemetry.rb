# frozen_string_literal: true

module Atlas
  # OpenTelemetry for the Backend API client, with no dependency: it is active only when the +opentelemetry+ API
  # (the +opentelemetry-api+ gem) is already loaded in your process, and the SDK never requires it. Each call is a
  # client span +atlas METHOD /v1/...+ with +http.request.method+, +url.path+, +http.response.status_code+,
  # +atlas.retry_count+ and, on failure, the exception and an error status. When the metrics API is loaded too
  # (+opentelemetry-metrics-api+) it records +atlas.client.request.duration+ (seconds) and +atlas.client.requests+.
  #
  # Pass +telemetry: false+ to {Atlas::Client} to turn it off.
  module Telemetry
    module_function

    # @return [Boolean] whether the OpenTelemetry API is loaded.
    def available? = defined?(::OpenTelemetry) && ::OpenTelemetry.respond_to?(:tracer_provider)

    # Run the block inside a span (when enabled) and yield a callable that records the retry count.
    def trace(verb, path, enabled: nil)
      return yield(nil) if enabled == false || !available?

      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      retries = 0
      tracer.in_span("atlas #{verb} #{path}", attributes: { "http.request.method" => verb, "url.path" => path.to_s, "rpc.system" => "atlas" },
                                              kind: :client) do |span|
        result = yield(->(n) { retries = n })
        status = result.is_a?(Array) ? result[0] : nil
        span.set_attribute("http.response.status_code", status) if status
        span.set_attribute("atlas.retry_count", retries)
        span.status = ::OpenTelemetry::Trace::Status.error("HTTP #{status}") if status && status >= 400 && span.respond_to?(:status=)
        record(verb, status, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
        result
      end
    end

    def tracer
      @tracer ||= ::OpenTelemetry.tracer_provider.tracer("atlas-auth", Atlas::VERSION)
    end

    def record(verb, status, seconds)
      return unless ::OpenTelemetry.respond_to?(:meter_provider)

      @meter ||= ::OpenTelemetry.meter_provider.meter("atlas-auth", Atlas::VERSION)
      @duration ||= @meter.create_histogram("atlas.client.request.duration", unit: "s", description: "Backend API call duration")
      @count ||= @meter.create_counter("atlas.client.requests", description: "Backend API calls")
      attrs = { "http.request.method" => verb, "http.response.status_code" => status.to_i }
      @duration.record(seconds, attributes: attrs)
      @count.add(1, attributes: attrs)
    rescue StandardError
      nil # telemetry must never break a request
    end
  end
end
