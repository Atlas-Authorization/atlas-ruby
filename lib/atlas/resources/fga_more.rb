# frozen_string_literal: true

require_relative "fga"

module Atlas
  module Resources
    class Fga
      # List the users that have a relation on an object, filtered to one user type (or to
      # +type#relation+ usersets via +user_filters[0].relation+). Exact for wildcards (+type:*+ plus
      # +excluded_users+ under +but not+), nested groups and contextual tuples; tuple conditions are
      # evaluated against +context+. Pages with +page_size+ / +continuation_token+; +consistency+ /
      # +consistency_token+ behave as on check.
      # Scope: fga:read. query: dry_run.
      def list_users(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/fga/stores/#{enc(id)}/list-users",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read the store’s tuple changelog: every tuple write and delete in commit order, resumable
      # with +continuation_token+ (returned even on the last page — pass it later to receive only
      # newer changes). Filter by object +type+ and +start_time+.
      # Scope: fga:read. query: type, page_size, continuation_token, start_time, limit,
      # starting_after.
      def read_changes(id, query = nil)
        request(method: :get, path: "/v1/fga/stores/#{enc(id)}/changes", query: query)
      end
    end
  end
end
