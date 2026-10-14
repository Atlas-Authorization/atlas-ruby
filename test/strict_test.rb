# frozen_string_literal: true

require_relative "test_helper"

# Strict request bodies (Atlas-Strict) and the Atlas-Unknown-Fields warning.
class StrictTest < Minitest::Test
  def setup
    @http = Atlas::Test::StubRequester.new
  end

  def test_no_strict_header_by_default
    client = Atlas::Client.new("sk_test_1", http: @http)
    @http.enqueue(body: {})
    client.users.update("user_1", { first_name: "Ada" })
    refute @http.last.headers.key?("atlas-strict")
  end

  def test_client_level_strict_is_sent_on_writes_only
    client = Atlas::Client.new("sk_test_1", http: @http, strict: true)
    @http.enqueue(body: {})
    client.users.update("user_1", { first_name: "Ada" })
    assert_equal "true", @http.last.headers["atlas-strict"]

    @http.enqueue(body: {})
    client.users.delete("user_1")
    assert_equal "true", @http.last.headers["atlas-strict"]

    @http.enqueue(body: {})
    client.users.get("user_1")
    refute @http.last.headers.key?("atlas-strict")
  end

  def test_per_call_override_with_options
    client = Atlas::Client.new("sk_test_1", http: @http, strict: true)
    @http.enqueue(body: {})
    client.with_options(strict: false).users.update("user_1", { legacy: 1 })
    assert_equal "false", @http.last.headers["atlas-strict"]

    # The original client is unchanged.
    @http.enqueue(body: {})
    client.users.update("user_1", { first_name: "Ada" })
    assert_equal "true", @http.last.headers["atlas-strict"]

    lenient = Atlas::Client.new("sk_test_1", http: @http)
    @http.enqueue(body: {})
    lenient.with_options(strict: true).organizations.create({ name: "Acme" })
    assert_equal "true", @http.last.headers["atlas-strict"]
  end

  def test_transport_request_accepts_a_strict_override
    client = Atlas::Client.new("sk_test_1", http: @http)
    @http.enqueue(body: {})
    client.transport.request(method: :post, path: "/v1/users", body: { email_address: "a@b.c" }, strict: true)
    assert_equal "true", @http.last.headers["atlas-strict"]
  end

  def test_strict_rejection_surfaces_unknown_field_errors
    client = Atlas::Client.new("sk_test_1", http: @http, strict: true)
    @http.enqueue(status: 422, body: { "errors" => [
      { "code" => "UNKNOWN_FIELD", "message" => "Unknown field \"nmae\"", "param" => "nmae" }
    ] })
    error = assert_raises(Atlas::UnprocessableEntityError) { client.users.update("user_1", { nmae: "x" }) }
    assert_equal "UNKNOWN_FIELD", error.code
    assert_equal "nmae", error.errors.first["param"]
  end

  def test_unknown_fields_header_reaches_the_callback
    seen = []
    client = Atlas::Client.new("sk_test_1", http: @http, on_unknown_fields: ->(w) { seen << w })
    @http.enqueue(body: { "id" => "user_1" }, headers: { "Atlas-Unknown-Fields" => "nmae, profile.colour" })
    result = client.users.update("user_1", { nmae: "x" })

    assert_equal "user_1", result["id"]
    assert_equal 1, seen.length
    assert_equal %w[nmae profile.colour], seen.first.fields
    assert_equal "PATCH", seen.first.method
    assert_equal "/v1/users/user_1", seen.first.path
  end

  def test_callback_not_called_without_the_header_and_errors_are_swallowed
    calls = 0
    client = Atlas::Client.new("sk_test_1", http: @http, on_unknown_fields: ->(_w) { calls += 1 })
    @http.enqueue(body: {}, headers: { "content-type" => "application/json" })
    client.users.update("user_1", { first_name: "A" })
    assert_equal 0, calls

    boom = Atlas::Client.new("sk_test_1", http: @http, on_unknown_fields: ->(_w) { raise "boom" })
    @http.enqueue(body: { "ok" => true }, headers: { "atlas-unknown-fields" => "x" })
    assert_equal true, boom.users.update("user_1", { x: 1 })["ok"]
  end
end
