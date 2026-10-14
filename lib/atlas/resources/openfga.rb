# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/openfga+ — openFGA-compatible relationship-based authorization (stores, models, tuples, checks).
    class OpenFga < Base
      # +GET /v1/openfga/stores+ — the instance's OpenFGA stores.
      def list_stores(params = {})
        request(method: :get, path: "/v1/openfga/stores", query: params)
      end

      # +POST /v1/openfga/stores+ — create an OpenFGA store.
      def create_store(name, idempotency_key: nil)
        request(method: :post, path: "/v1/openfga/stores", body: { name: name }, idempotency_key: idempotency_key)
      end

      # +GET /v1/openfga/stores/:store+ — one OpenFGA store.
      def get_store(store_id)
        request(method: :get, path: "/v1/openfga/stores/#{enc(store_id)}")
      end

      # +POST /v1/openfga/stores/:store/authorization-models+ — write a new authorization model (type_definitions + schema_version, or dsl).
      def write_authorization_model(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/authorization-models", body: body)
      end

      # +GET /v1/openfga/stores/:store/authorization-models+ — the authorization models in a store.
      def list_authorization_models(store_id, params = {})
        request(method: :get, path: "/v1/openfga/stores/#{enc(store_id)}/authorization-models", query: params)
      end

      # +GET /v1/openfga/stores/:store/authorization-models/:mid+ — one authorization model.
      def get_authorization_model(store_id, model_id)
        request(method: :get, path: "/v1/openfga/stores/#{enc(store_id)}/authorization-models/#{enc(model_id)}")
      end

      # +POST /v1/openfga/stores/:store/check+ — check whether a user has a relation on an object.
      def check(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/check", body: body)
      end

      # +POST /v1/openfga/stores/:store/batch-check+ — check up to 100 tuples in one request, keyed by correlation id.
      def batch_check(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/batch-check", body: body)
      end

      # +POST /v1/openfga/stores/:store/expand+ — expand the userset tree for an object and relation.
      def expand(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/expand", body: body)
      end

      # +POST /v1/openfga/stores/:store/list-objects+ — list the objects of a type a user has a relation on.
      def list_objects(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/list-objects", body: body)
      end

      # +POST /v1/openfga/stores/:store/read+ — read relationship tuples, optionally filtered by a tuple key.
      def read(store_id, body = {})
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/read", body: body)
      end

      # +POST /v1/openfga/stores/:store/write+ — write and/or delete relationship tuples.
      def write(store_id, body)
        request(method: :post, path: "/v1/openfga/stores/#{enc(store_id)}/write", body: body)
      end
    end
  end
end
