# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/fga+ — fine-grained relationship-based authorization (Zanzibar /
    # OpenFGA). A tenant owns stores; each holds versioned models and the
    # relationship tuples the engine resolves.
    class Fga < Base
      # +fga.stores+ — store CRUD.
      def stores
        @stores ||= Stores.new(@transport)
      end

      # +fga.models+ — authorization models within a store.
      def models
        @models ||= Models.new(@transport)
      end

      # Write and/or delete tuples in one atomic call.
      def write(store_id, body, idempotency_key: nil)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/write", body: body, idempotency_key: idempotency_key)
      end

      # Query stored tuples by any of user / relation / object.
      def read(store_id, body)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/read", body: body)
      end

      # Resolve a single access question against the model.
      def check(store_id, body)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/check", body: body)
      end

      # Resolve MANY access questions in one round trip.
      def batch_check(store_id, body)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/batch-check", body: body)
      end

      # List the objects of a type a user has a relation to.
      def list_objects(store_id, body)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/list-objects", body: body)
      end

      # Expand the full userset tree for an object#relation.
      def expand(store_id, body)
        request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/expand", body: body)
      end

      # Bind a default store so an app that uses one store can call
      # +fga.store(id).check(...)+ instead of threading the store id through
      # every call. Returns the same operations with +store_id+ pre-applied.
      def store(store_id)
        StoreScope.new(self, store_id)
      end

      class Stores < Base
        def list
          request(method: :get, path: "/v1/fga/stores")
        end

        def create(body, idempotency_key: nil)
          request(method: :post, path: "/v1/fga/stores", body: body, idempotency_key: idempotency_key)
        end

        def get(id)
          request(method: :get, path: "/v1/fga/stores/#{enc(id)}")
        end

        def delete(id)
          request(method: :delete, path: "/v1/fga/stores/#{enc(id)}")
        end
      end

      class Models < Base
        def list(store_id)
          request(method: :get, path: "/v1/fga/stores/#{enc(store_id)}/authorization-models")
        end

        def create(store_id, body, idempotency_key: nil)
          request(method: :post, path: "/v1/fga/stores/#{enc(store_id)}/authorization-models", body: body, idempotency_key: idempotency_key)
        end

        def get(store_id, model_id)
          request(method: :get, path: "/v1/fga/stores/#{enc(store_id)}/authorization-models/#{enc(model_id)}")
        end
      end

      # A store-bound view of the operations, so callers skip the store id.
      class StoreScope
        def initialize(fga, store_id)
          @fga = fga
          @store_id = store_id
        end

        def write(body, idempotency_key: nil)
          @fga.write(@store_id, body, idempotency_key: idempotency_key)
        end

        def read(body)
          @fga.read(@store_id, body)
        end

        def check(body)
          @fga.check(@store_id, body)
        end

        def batch_check(body)
          @fga.batch_check(@store_id, body)
        end

        def list_objects(body)
          @fga.list_objects(@store_id, body)
        end

        def expand(body)
          @fga.expand(@store_id, body)
        end

        def models
          @models ||= BoundModels.new(@fga, @store_id)
        end

        class BoundModels
          def initialize(fga, store_id)
            @fga = fga
            @store_id = store_id
          end

          def list
            @fga.models.list(@store_id)
          end

          def create(body, idempotency_key: nil)
            @fga.models.create(@store_id, body, idempotency_key: idempotency_key)
          end

          def get(model_id)
            @fga.models.get(@store_id, model_id)
          end
        end
      end
    end
  end
end
