# frozen_string_literal: true

module Atlas
  # Support for the generated catalog (lib/atlas/generated): response models, pages and the
  # helpers the generated methods call.
  module Generated
    # "Argument not given": an optional keyword left at UNSET is left out of the request, so an
    # explicit +nil+ still sends JSON +null+ (to clear a field).
    UNSET = Object.new.tap do |o|
      def o.inspect = "UNSET"
      def o.to_s = "UNSET"
    end.freeze

    # Drop the UNSET entries of a request body or query Hash.
    def self.compact(hash)
      hash.reject { |_, v| v.equal?(UNSET) }
    end

    # Wrap a response Hash in +klass+; anything that is not a Hash (nil, a list, text) passes through.
    def self.wrap(klass, value)
      value.is_a?(Hash) ? klass.new(value) : value
    end

    # Fetch the first page of a list now; the returned {Page} fetches the rest as it is walked.
    def self.page(item_model, query, envelope: nil, &fetch)
      Page.new(fetch.call(query), item_model, query, envelope: envelope, &fetch)
    end

    # One page of a cursor-paginated list. It is Enumerable over *every* item: +each+ (and so
    # +map+, +select+, +first(n)+, +lazy+, +to_a+) fetches the following pages as it goes, using
    # the +next_cursor+ the API returned (or the last item's id).
    #
    #   atlas.chat_integrations.list_chat_integrations.each { |i| puts i.name }
    #   page = atlas.iga.list_bundles(limit: 50)   # first page already loaded
    #   page.data        # this page's items       page.has_more?   # more pages exist
    class Page
      include Enumerable

      # @return [Hash] the raw page body.
      attr_reader :raw

      def initialize(raw, item_model, query = {}, envelope: nil, &fetch)
        @raw = raw.is_a?(Hash) ? raw : {}
        @item_model = item_model
        @envelope = envelope
        @query = query || {}
        @fetch = fetch
      end

      # This page's items, as models.
      def data
        Array(@raw["data"]).map { |item| item.is_a?(Hash) && @item_model ? @item_model.new(item) : item }
      end

      def has_more? = @raw["has_more"] == true

      def next_cursor
        @raw["next_cursor"] || (has_more? ? Array(@raw["data"]).last&.then { |i| i.is_a?(Hash) ? i["id"] : nil } : nil)
      end

      # The following page, or nil.
      def next_page
        cursor = next_cursor
        return nil unless @fetch && has_more? && cursor

        query = Generated.compact(@query.merge("starting_after" => cursor))
        Page.new(@fetch.call(query), @item_model, query, envelope: @envelope, &@fetch)
      end

      # The whole answer as a model, for lists that carry more than the items (a catalog, totals,
      # defaults); nil when the answer is only the page.
      def envelope = @envelope&.new(@raw)

      # Yield each page (this one first).
      def each_page
        return enum_for(:each_page) unless block_given?

        page = self
        while page
          yield page
          page = page.next_page
        end
      end

      def each(&block)
        return enum_for(:each) unless block

        each_page { |page| page.data.each(&block) }
      end

      def [](key) = @raw[key.to_s]
      def to_h = @raw
    end
  end

  # Base class of the generated response models.
  #
  # A model wraps the response Hash. +attribute+ declares a typed reader; a type is one of
  # +:string+, +:integer+, +:number+, +:boolean+, +:hash+, +:any+, a model name (+"User"+, looked
  # up in {Atlas::Models}), +[type]+ for a list or +{ map: type }+ for a map of that type.
  # Hash-style reads (+model["id"]+, +dig+, +to_h+) keep working and see fields the SDK does
  # not declare yet.
  class Model
    class << self
      # @return [Hash{Symbol=>Array}] reader name => [json key, type]
      def attributes
        @attributes ||= {}
      end

      def attribute(name, key, type = :any)
        attributes[name] = [key, type]
        define_method(name) { Model.coerce(@raw[key], type) }
      end

      # Wrap an operation's answer: +Atlas::Models.wrap("GET /v1/users/{id}", hash)+.
      def wrap_operation(operation, value)
        spec = Models::OPERATIONS[operation]
        return value if spec.nil? || !value.is_a?(Hash)

        if spec.include?("[]")
          item, env = spec.split("[]", 2)
          env = env.delete_prefix(":")
          Generated::Page.new(value, item.empty? ? nil : Models.const_get(item),
                              envelope: env.empty? ? nil : Models.const_get(env))
        else
          Models.const_get(spec).new(value)
        end
      end
    end

    # Convert a raw JSON value to its declared type.
    def self.coerce(value, type)
      return value if value.nil?

      case type
      when String
        value.is_a?(Hash) ? Models.const_get(type).new(value) : value
      when Array
        value.is_a?(Array) ? value.map { |v| coerce(v, type[0]) } : value
      when Hash
        value.is_a?(Hash) ? value.transform_values { |v| coerce(v, type[:map]) } : value
      else
        value
      end
    end

    # @param raw [Hash] the response body (string keys).
    def initialize(raw = {})
      @raw = raw.is_a?(Hash) ? raw : {}
    end

    def [](key) = @raw[key.to_s]
    def dig(*keys) = @raw.dig(*keys.map(&:to_s))
    def key?(key) = @raw.key?(key.to_s)
    def to_h = @raw
    def ==(other) = other.is_a?(Model) ? other.class == self.class && other.to_h == @raw : @raw == other
    alias eql? ==
    def hash = @raw.hash
    def inspect = "#<#{self.class.name} #{@raw.inspect}>"
  end

  module Models
    # Wrap a hand-written call's answer in its typed model:
    #   Atlas::Models.wrap("GET /v1/users/{id}", atlas.users.get("user_1"))
    def self.wrap(operation, value)
      Model.wrap_operation(operation, value)
    end
  end

  # Checked request builders for the operations you call through a hand-written resource that
  # takes a plain Hash:
  #
  #   atlas.users.create(Atlas::Requests.body("POST /v1/users", email_address: "ada@example.com"))
  #
  # Field names are snake_case; an unknown field or a missing required one raises ArgumentError
  # before any request is made.
  module Requests
    def self.snake(name)
      name.to_s.gsub(/([A-Z]+)([A-Z][a-z])/, '\\1_\\2').gsub(/([a-z0-9])([A-Z])/, '\\1_\\2')
          .gsub(/[^A-Za-z0-9]+/, "_").gsub(/\A_+|_+\z/, "").downcase
    end

    def self.spec(operation)
      FIELDS.fetch(operation) { raise ArgumentError, "no request fields known for #{operation.inspect}" }
    end

    # @param operation [String] e.g. +"POST /v1/users"+
    # @return [Hash{String=>Object}] the JSON body.
    def self.body(operation, **fields)
      s = spec(operation)
      names = (s["body"] || {}).keys.to_h { |k| [snake(k), k] }
      unknown = fields.keys.map(&:to_s) - names.keys
      raise ArgumentError, "unknown field(s) for #{operation}: #{unknown.join(', ')}" unless unknown.empty?

      missing = (s["required"] || []).reject { |k| fields.key?(names.key(k).to_sym) }
      raise ArgumentError, "missing required field(s) for #{operation}: #{missing.join(', ')}" unless missing.empty?

      fields.to_h { |k, v| [names.fetch(k.to_s), v] }
    end

    # @return [Hash{String=>Object}] the query parameters.
    def self.query(operation, **params)
      s = spec(operation)
      names = (s["query"] || []).to_h { |k| [snake(k), k] }
      unknown = params.keys.map(&:to_s) - names.keys
      raise ArgumentError, "unknown query parameter(s) for #{operation}: #{unknown.join(', ')}" unless unknown.empty?

      params.to_h { |k, v| [names.fetch(k.to_s), v] }
    end
  end
end
