# frozen_string_literal: true

module Atlas
  # Cursor-pagination helpers.
  #
  # Walk every page of a cursor-paginated BAPI list, yielding items one at a
  # time. Works with any resource +list+ that takes +limit+/+starting_after+
  # (plus any route-specific filters) and returns a
  # +{ "data", "has_more", "next_cursor" }+ page — +users.list+,
  # +organizations.list+, +invitations.list+, +audit_logs.list+, +waitlist.list+.
  #
  #   Atlas.paginate(client.users).each { |user| puts user["id"] }
  #   Atlas.paginate(client.users, status: "active").to_a
  #
  # Kept as free functions rather than bolted onto every return value: the page
  # is the primitive most callers want, and a caller who needs the whole set
  # opts into the extra round trips explicitly.
  module Pagination
    module_function

    # Yield every item across every cursor page. Returns an Enumerator when no
    # block is given, so +.each+, +.map+, +.lazy+, +.first(n)+ all work.
    #
    # @param resource [#list] anything exposing a +list(params)+ method.
    # @param params [Hash] filters passed through on every page request.
    def paginate(resource, params = {}, &block)
      return enum_for(:paginate, resource, params) unless block_given?

      cursor = params[:starting_after] || params["starting_after"]
      loop do
        page = resource.list(params.merge(starting_after: cursor))
        (page["data"] || []).each(&block)
        cursor = page["next_cursor"]
        break if !page["has_more"] || cursor.nil?
      end
    end

    # Collect every page of a cursor-paginated list into a single array.
    def collect(resource, params = {})
      paginate(resource, params).to_a
    end
  end

  # Convenience delegators so callers write +Atlas.paginate(...)+.
  def self.paginate(resource, params = {}, &block)
    Pagination.paginate(resource, params, &block)
  end

  def self.collect(resource, params = {})
    Pagination.collect(resource, params)
  end
end
