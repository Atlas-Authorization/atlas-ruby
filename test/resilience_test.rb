# frozen_string_literal: true

require_relative "test_helper"

class ResilienceTest < Minitest::Test
  def client(stub, **opts)
    Atlas::Client.new("sk_test_x", api_url: "https://api.test", http: stub, **opts)
  end

  def policy(sleeps, **opts)
    Atlas::RetryPolicy.new(sleeper: ->(s) { sleeps << s }, random: -> { 1.0 }, **opts)
  end

  def test_no_retries_by_default
    stub = Atlas::Test::StubRequester.new.enqueue(status: 503, body: { "errors" => [{ "code" => "X", "message" => "m" }] })
    assert_raises(Atlas::ServerError) { client(stub).instance.get }
    assert_equal 1, stub.requests.size
  end

  def test_retries_429_honouring_retry_after_and_503_with_backoff
    sleeps = []
    stub = Atlas::Test::StubRequester.new
    stub.enqueue(status: 429, body: {}, headers: { "retry-after" => "3" })
    stub.enqueue(status: 503, body: {})
    stub.enqueue(status: 200, body: { "ok" => true })
    result = client(stub, retry_policy: policy(sleeps, max_retries: 3)).instance.get
    assert_equal({ "ok" => true }, result)
    assert_equal [3.0, 1.0], sleeps
  end

  def test_retry_after_is_capped_and_http_dates_parse
    p = Atlas::RetryPolicy.new(max_delay: 10)
    assert_equal 10, p.delay(0, "999")
    assert_in_delta 5, p.delay(0, (Time.now + 5).httpdate), 1.5
  end

  def test_post_without_idempotency_key_is_not_retried_but_with_one_it_is
    sleeps = []
    stub = Atlas::Test::StubRequester.new.enqueue(status: 503, body: {})
    assert_raises(Atlas::ServerError) { client(stub, retry_policy: policy(sleeps)).waitlist.create("a@b.c") }
    assert_equal 1, stub.requests.size
    stub = Atlas::Test::StubRequester.new.enqueue(status: 503, body: {}).enqueue(status: 200, body: { "id" => "x" })
    assert_equal({ "id" => "x" }, client(stub, retry_policy: policy(sleeps)).users.create({ email_address: "a@b.c" }, idempotency_key: "k1"))
  end

  def test_gives_up_after_max_retries
    sleeps = []
    stub = Atlas::Test::StubRequester.new
    3.times { stub.enqueue(status: 503, body: {}) }
    assert_raises(Atlas::ServerError) { client(stub, retry_policy: policy(sleeps, max_retries: 2)).instance.get }
    assert_equal 3, stub.requests.size
    assert_equal 2, sleeps.size
  end

  def test_status_aware_stops_retrying_during_a_major_outage
    sleeps = []
    stub = Atlas::Test::StubRequester.new
    stub.enqueue(status: 503, body: {})
    stub.enqueue(status: 200, body: { "object" => "status", "status" => "degraded", "components" => [{ "id" => "backend_api", "status" => "major_outage" }] })
    assert_raises(Atlas::ServerError) { client(stub, retry_policy: policy(sleeps, status_aware: true)).instance.get }
    assert_empty sleeps
    assert_equal "https://api.test/v1/status", stub.requests.last.url
  end

  def test_status_aware_keeps_retrying_when_only_degraded
    sleeps = []
    stub = Atlas::Test::StubRequester.new
    stub.enqueue(status: 503, body: {})
    stub.enqueue(status: 200, body: { "object" => "status", "status" => "degraded", "components" => [] })
    stub.enqueue(status: 200, body: { "ok" => 1 })
    assert_equal({ "ok" => 1 }, client(stub, retry_policy: policy(sleeps, status_aware: true)).instance.get)
  end

  def test_network_errors_are_retried
    sleeps = []
    calls = 0
    http = lambda do |*|
      calls += 1
      raise Errno::ECONNRESET if calls == 1

      [200, "{}", {}]
    end
    client(http, retry_policy: policy(sleeps)).instance.get
    assert_equal 2, calls
  end

  # A stand-in for the OpenTelemetry API: loaded only by this test.
  module FakeOtel
    Span = Struct.new(:attrs, :status) do
      def set_attribute(k, v) = (attrs[k] = v)
    end

    class Tracer
      attr_reader :spans
      def initialize = (@spans = [])

      def in_span(name, attributes: {}, kind: nil)
        span = Span.new(attributes.dup, nil)
        @spans << [name, span]
        yield span
      end
    end
  end

  def test_telemetry_wraps_calls_in_a_span_only_when_opentelemetry_is_loaded
    stub = Atlas::Test::StubRequester.new.enqueue(status: 200, body: {})
    refute Atlas::Telemetry.available?
    client(stub).instance.get # no OpenTelemetry: plain call
    tracer = FakeOtel::Tracer.new
    otel = Module.new
    otel.define_singleton_method(:tracer_provider) { Struct.new(:t) { def tracer(*) = t }.new(tracer) }
    Object.const_set(:OpenTelemetry, otel)
    Atlas::Telemetry.instance_variable_set(:@tracer, nil)
    begin
      stub.enqueue(status: 200, body: {})
      client(stub).instance.get
      name, span = tracer.spans.last
      assert_equal "atlas GET /v1/instance", name
      assert_equal 200, span.attrs["http.response.status_code"]
      stub.enqueue(status: 200, body: {})
      client(stub, telemetry: false).instance.get
      assert_equal 1, tracer.spans.size
    ensure
      Object.send(:remove_const, :OpenTelemetry)
      Atlas::Telemetry.instance_variable_set(:@tracer, nil)
    end
  end

  def test_doctor_reports_key_skew_jwks_status_and_access
    date = (Time.now - 90).httpdate
    http = lambda do |_m, url, _h, _b|
      case URI.parse(url).path
      when "/v1/status" then [200, JSON.generate("status" => "operational", "components" => []), { "date" => date }]
      when "/v1/jwks" then [200, JSON.generate("keys" => [{ "kid" => "k" }]), {}]
      when "/v1/instance" then [401, JSON.generate("errors" => [{ "code" => "UNAUTHENTICATED", "message" => "no" }]), {}]
      else [404, "{}", {}]
      end
    end
    report = client(http).doctor(jwks_url: "https://api.test/v1/jwks", issuer: "http://api.test")
    by = report.checks.to_h { |c| [c.name, c] }
    assert_equal :ok, by["secret key"].status
    assert_equal :fail, by["clock skew"].status
    assert_equal :ok, by["jwks"].status
    assert_equal :ok, by["instance status"].status
    assert_equal :warn, by["config"].status
    assert_equal :fail, by["api access"].status
    refute report.ok?
    assert_includes report.to_s, "FAIL"
    bad = Atlas::Client.new("pk_live_x", http: http).doctor
    assert_equal :fail, bad.checks.first.status
  end
end
