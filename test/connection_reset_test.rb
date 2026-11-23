# frozen_string_literal: true

require_relative "test_helper"

# A connection reset before any response is retried once for safe requests; nothing else is.
class ConnectionResetTest < Minitest::Test
  # Raises +error+ on the first +fail_times+ calls, then answers 200 {}.
  class Flaky
    attr_reader :calls

    def initialize(error, fail_times: 1)
      @error = error
      @fail_times = fail_times
      @calls = 0
    end

    def call(_method, _url, _headers, _body)
      @calls += 1
      raise @error, "reset" if @calls <= @fail_times

      [200, "{}", {}]
    end
  end

  def transport(http)
    Atlas::Transport.new(secret_key: "sk_test_123", http: http)
  end

  def test_get_is_retried_once
    http = Flaky.new(Errno::ECONNRESET)
    transport(http).request(method: :get, path: "/v1/users")
    assert_equal 2, http.calls
  end

  def test_keyed_post_is_retried_once
    http = Flaky.new(EOFError)
    transport(http).request(method: :post, path: "/v1/users", body: {}, idempotency_key: "k1")
    assert_equal 2, http.calls
  end

  def test_plain_post_is_not_retried
    http = Flaky.new(Errno::ECONNRESET)
    assert_raises(Errno::ECONNRESET) { transport(http).request(method: :post, path: "/v1/users", body: {}) }
    assert_equal 1, http.calls
  end

  def test_timeout_is_not_retried_and_a_second_reset_is_raised
    slow = Flaky.new(Net::ReadTimeout)
    assert_raises(Net::ReadTimeout) { transport(slow).request(method: :get, path: "/v1/users") }
    assert_equal 1, slow.calls

    twice = Flaky.new(Errno::EPIPE, fail_times: 2)
    assert_raises(Errno::EPIPE) { transport(twice).request(method: :get, path: "/v1/users") }
    assert_equal 2, twice.calls
  end
end
