# frozen_string_literal: true

require_relative "openfga"

module Atlas
  module Resources
    class OpenFga
      # List the users that have a relation on an object (OpenFGA-wire ListUsers): concrete users,
      # usersets (+user_filters[0].relation+), and the +type:*+ wildcard with +excluded_users+.
      # Honours contextual tuples and tuple conditions; pages with +page_size+ /
      # +continuation_token+.
      # Scope: fga:read. query: dry_run. body requires: object, relation, user_filters.
      def list_users(store, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/openfga/stores/#{enc(store)}/list-users",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read the tuple changelog (OpenFGA-wire ReadChanges): every tuple write and delete in order,
      # resumable with +continuation_token+ (the token is returned even on the last page — pass it
      # later to receive only newer changes).
      # Scope: fga:read. query: type, page_size, continuation_token, start_time.
      def read_changes(store, query = nil)
        request(method: :get, path: "/v1/openfga/stores/#{enc(store)}/changes", query: query)
      end
    end
  end
end
