# frozen_string_literal: true

require_relative "test_helper"

class GeneratedModelsTest < Minitest::Test
  def client(stub) = Atlas::Client.new("sk_test_x", api_url: "https://api.test", http: stub)

  def test_models_have_typed_accessors_and_keep_raw_access
    model = Atlas::Models::ChatIntegration.new("id" => "ci_1", "provider" => "slack", "enabled" => true, "future" => 1)
    assert_equal "ci_1", model.id
    assert_equal true, model.enabled
    assert_equal 1, model["future"]
    assert_equal "slack", model.to_h["provider"]
    assert_equal model, Atlas::Models::ChatIntegration.new(model.to_h)
  end

  def test_lists_are_enumerable_and_walk_every_page
    stub = Atlas::Test::StubRequester.new
    stub.enqueue(body: { "object" => "list", "data" => [{ "id" => "a" }, { "id" => "b" }], "has_more" => true, "next_cursor" => "b" })
    stub.enqueue(body: { "object" => "list", "data" => [{ "id" => "c" }], "has_more" => false })
    page = client(stub).chat_integrations.list_chat_integrations(limit: 2)
    assert_equal 2, page.data.size
    assert_equal %w[a b c], page.map(&:id)
    assert_includes stub.requests.last.url, "starting_after=b"
  end

  def test_optional_fields_are_omitted_and_nil_is_sent_as_null
    stub = Atlas::Test::StubRequester.new.enqueue(body: {})
    client(stub).chat_integrations.create_chat_integration(provider: "slack", name: "n", credentials: {}, config: nil, idempotency_key: "k")
    body = JSON.parse(stub.last.body)
    assert_equal({ "provider" => "slack", "name" => "n", "credentials" => {}, "config" => nil }, body)
    assert_equal "k", stub.last.headers["idempotency-key"]
  end

  def test_wrap_a_hand_written_answer_and_build_checked_requests
    wrapped = Atlas::Models.wrap("GET /v1/instance", { "object" => "instance" })
    assert_kind_of Atlas::Model, wrapped
    body = Atlas::Requests.body("POST /v1/users", email_address: "a@b.c")
    assert_equal({ "email_address" => "a@b.c" }, body)
    assert_raises(ArgumentError) { Atlas::Requests.body("POST /v1/users", bogus: 1) }
  end

  def test_no_catalog_group_shadows_a_hand_written_method
    # a generated method on an existing resource must not replace a hand-written one
    assert_equal Atlas::Resources::Users.instance_method(:get).owner, Atlas::Resources::Users
  end
end
