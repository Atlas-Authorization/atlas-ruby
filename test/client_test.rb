# frozen_string_literal: true

require_relative "test_helper"

# Exercises the transport contract through the real resource namespaces:
# method -> path -> auth header -> body -> decoded return, plus the §9.1 error
# envelope and cursor pagination. No network — every call is answered by the
# injected StubRequester.
class ClientTest < Minitest::Test
  def setup
    @http = Atlas::Test::StubRequester.new
    @client = Atlas::Client.new("sk_test_123", http: @http)
  end

  def test_requires_a_secret_key
    assert_raises(Atlas::ConfigurationError) { Atlas::Client.new("", http: @http) }
    assert_raises(Atlas::ConfigurationError) { Atlas::Client.new(nil, http: @http) }
  end

  def test_users_list_is_a_get_with_bearer_auth
    @http.enqueue(body: { "object" => "list", "data" => [{ "id" => "user_1" }] })
    result = @client.users.list

    req = @http.last
    assert_equal "GET", req.method
    assert_equal "https://api.atlasauth.net/v1/users", req.url
    assert_equal "Bearer sk_test_123", req.headers["authorization"]
    assert_nil req.body
    assert_equal "user_1", result["data"][0]["id"]
  end

  def test_users_get_encodes_the_id_in_the_path
    @http.enqueue(body: { "id" => "user_abc" })
    @client.users.get("user_abc")
    assert_equal "https://api.atlasauth.net/v1/users/user_abc", @http.last.url
  end

  def test_users_create_posts_json_with_optional_idempotency_key
    @http.enqueue(status: 201, body: { "id" => "user_new" })
    result = @client.users.create({ email_address: "ada@example.com" }, idempotency_key: "idem_1")

    req = @http.last
    assert_equal "POST", req.method
    assert_equal "https://api.atlasauth.net/v1/users", req.url
    assert_equal "application/json", req.headers["content-type"]
    assert_equal "idem_1", req.headers["idempotency-key"]
    assert_equal({ "email_address" => "ada@example.com" }, JSON.parse(req.body))
    assert_equal "user_new", result["id"]
  end

  def test_query_params_are_serialized_dropping_nil_and_spreading_arrays
    @http.enqueue(body: { "data" => [] })
    @client.users.list(limit: 2, order: nil, email_address: %w[a@x.com b@x.com])

    url = @http.last.url
    assert_includes url, "limit=2"
    refute_includes url, "order="
    assert_includes url, "email_address=a%40x.com"
    assert_includes url, "email_address=b%40x.com"
  end

  def test_sessions_organizations_roles_reach_their_paths
    @http.enqueue(body: { "id" => "sess_1" })
    @client.sessions.get("sess_1")
    assert_equal "https://api.atlasauth.net/v1/sessions/sess_1", @http.last.url

    @http.enqueue(body: { "id" => "org_1" })
    @client.organizations.get("org_1")
    assert_equal "https://api.atlasauth.net/v1/organizations/org_1", @http.last.url

    @http.enqueue(body: { "object" => "list", "data" => [] })
    @client.roles.list
    assert_equal "https://api.atlasauth.net/v1/roles", @http.last.url
  end

  def test_non_2xx_raises_a_typed_api_error_carrying_status_and_code
    @http.enqueue(status: 404, body: { "errors" => [{ "code" => "NOT_FOUND", "message" => "No such user." }] })

    error = assert_raises(Atlas::NotFoundError) { @client.users.get("user_missing") }
    assert_equal 404, error.status
    assert_equal "NOT_FOUND", error.code
    assert error.has_code?("NOT_FOUND")
    assert_includes error.message, "No such user."
    assert_kind_of Atlas::APIError, error
  end

  def test_401_and_409_map_to_their_subclasses
    @http.enqueue(status: 401, body: { "errors" => [{ "code" => "UNAUTHORIZED", "message" => "bad key" }] })
    assert_raises(Atlas::AuthenticationError) { @client.users.list }

    @http.enqueue(status: 409, body: { "errors" => [{ "code" => "IDENTIFIER_EXISTS", "message" => "dup" }] })
    assert_raises(Atlas::ConflictError) { @client.users.create({ email_address: "x@y.com" }) }
  end

  def test_204_returns_nil
    @http.enqueue(status: 204)
    assert_nil @client.users.delete("user_1")
  end

  def test_paginate_walks_every_cursor_page
    @http.enqueue(body: { "data" => [{ "id" => "a" }, { "id" => "b" }], "has_more" => true, "next_cursor" => "cur_2" })
    @http.enqueue(body: { "data" => [{ "id" => "c" }], "has_more" => false, "next_cursor" => nil })

    ids = Atlas.paginate(@client.users).map { |u| u["id"] }
    assert_equal %w[a b c], ids

    # The second request carried the cursor from the first page.
    assert_includes @http.requests[1].url, "starting_after=cur_2"
  end
end
