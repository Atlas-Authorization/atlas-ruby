# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

require_relative "error"

module Atlas
  # The default BAPI origin, overridable per instance via +api_url+.
  DEFAULT_API_URL = "https://api.atlasauth.net"

  # What the +on_unknown_fields:+ callback receives: the body fields a write
  # sent that the endpoint does not accept (and therefore ignored).
  UnknownFields = Struct.new(:fields, :method, :path, keyword_init: true)

  # The shared HTTP core every resource namespace calls.
  #
  # One place decides how a BAPI request is authenticated, serialized, and how a
  # failure becomes an {Atlas::APIError} — so a namespace method is a one-liner
  # naming a method, a path, and its shapes.
  #
  # The HTTP mechanism is injectable: pass +http:+ any object responding to
  # +call(method, url, headers, body)+ and returning +[status_integer,
  # body_string]+ (optionally a third element: a Hash of response headers,
  # which is how the +Atlas-Unknown-Fields+ warning is read). Tests use this to
  # run with no network; the default is a {Atlas::NetHTTPRequester} built on
  # Ruby's stdlib +Net::HTTP+.
  class Transport
    # Sentinel meaning "no body key was supplied", distinct from an explicit
    # empty hash (which is serialized to +{}+ with a content-type, matching the
    # TypeScript SDK's +body !== undefined+ gate).
    OMIT = :__atlas_omit__

    # Sentinel meaning "use the transport's configured strict setting" for a
    # single request (distinct from an explicit +true+/+false+ override).
    INHERIT = :__atlas_inherit__

    # HTTP methods that carry a write. +Atlas-Strict+ is only sent on these.
    WRITE_METHODS = %w[POST PUT PATCH DELETE].freeze

    # @return [Boolean, nil] the client-wide strict-body setting (nil = not sent).
    attr_reader :strict

    # @return [#call, nil] the unknown-fields callback, if any.
    attr_reader :on_unknown_fields

    # @return [String, nil] a W3C +traceparent+ sent on every request (nil = none).
    attr_reader :traceparent

    # @return [String, nil] an +x25519:<base64 public key>+ sent as +X-Secret-Recipient+ on every
    #   request, so every shown-once secret in an answer comes back sealed (+sealed_*+ fields,
    #   +secrets_sealed+). nil = none.
    attr_reader :secret_recipient

    def initialize(secret_key:, api_url: DEFAULT_API_URL, http: nil,
                   open_timeout: 30, read_timeout: 30, strict: nil, on_unknown_fields: nil, traceparent: nil,
                   secret_recipient: nil)
      raise ConfigurationError, "Atlas::Client requires a secret_key." if secret_key.nil? || secret_key.empty?

      @secret_key = secret_key
      @base = api_url || DEFAULT_API_URL
      @http = http || NetHTTPRequester.new(open_timeout: open_timeout, read_timeout: read_timeout)
      @strict = strict
      @on_unknown_fields = on_unknown_fields
      @traceparent = traceparent
      @secret_recipient = secret_recipient
    end

    # A copy of this transport with some settings replaced. The HTTP requester
    # (and its connection settings) is shared.
    def with(strict: INHERIT, on_unknown_fields: INHERIT, traceparent: INHERIT, secret_recipient: INHERIT)
      copy = dup
      copy.instance_variable_set(:@secret_recipient, secret_recipient) unless secret_recipient.equal?(INHERIT)
      copy.instance_variable_set(:@traceparent, traceparent) unless traceparent.equal?(INHERIT)
      copy.instance_variable_set(:@strict, strict) unless strict.equal?(INHERIT)
      copy.instance_variable_set(:@on_unknown_fields, on_unknown_fields) unless on_unknown_fields.equal?(INHERIT)
      copy
    end

    # Perform a request and return the parsed JSON (a Hash/Array), the raw text
    # when +raw:+ is true, or +nil+ for an empty/204 body.
    #
    # @param raw_body [String, nil] send these bytes as the request body instead
    #   of JSON (uploads). Requires +content_type:+.
    # @param content_type [String, nil] the content type of +raw_body+.
    # @param strict [Boolean, nil] override the client-wide strict setting for
    #   this one request: +true+ sends +Atlas-Strict: true+ (unknown body fields
    #   are refused with 422 UNKNOWN_FIELD), +false+ sends +Atlas-Strict: false+.
    # @raise [Atlas::APIError] on any non-2xx response.
    # @param headers [Hash, nil] extra request headers for this call (for example
    #   the end user's forwarded IP); they never replace the Bearer secret.
    def request(method:, path:, query: nil, body: OMIT, idempotency_key: nil, raw: false,
                raw_body: nil, content_type: nil, strict: INHERIT, headers: nil)
      verb = method.to_s.upcase
      url = join_url(@base, path) + serialize_query(query)

      extra = headers
      headers = {
        "authorization" => "Bearer #{@secret_key}",
        "accept" => "application/json"
      }

      payload = nil
      if raw_body
        raise ArgumentError, "raw_body needs a content_type" if content_type.nil? || content_type.to_s.empty?

        headers["content-type"] = content_type.to_s
        payload = raw_body.to_s.b
      elsif !body.equal?(OMIT)
        headers["content-type"] = "application/json"
        payload = JSON.generate(body)
      end
      headers["idempotency-key"] = idempotency_key if idempotency_key
      headers["traceparent"] = @traceparent if @traceparent && !@traceparent.to_s.empty?
      headers["x-secret-recipient"] = @secret_recipient if @secret_recipient && !@secret_recipient.to_s.empty?
      extra&.each do |name, value|
        key = name.to_s.downcase
        headers[key] = value.to_s unless key == "authorization" || value.nil?
      end

      effective_strict = strict.equal?(INHERIT) ? @strict : strict
      if !effective_strict.nil? && WRITE_METHODS.include?(verb)
        headers["atlas-strict"] = effective_strict ? "true" : "false"
      end

      status, text, response_headers = @http.call(verb, url, headers, payload)

      raise to_api_error(status, text) unless status.between?(200, 299)

      report_unknown_fields(response_headers, verb, path)

      return nil if status == 204 || text.nil? || text.empty?
      return text if raw

      JSON.parse(text)
    end

    private

    # Surface +Atlas-Unknown-Fields+ (body fields the endpoint ignored) to the
    # configured callback. Never raises: a broken callback must not turn a
    # successful write into an exception.
    def report_unknown_fields(response_headers, verb, path)
      return if @on_unknown_fields.nil? || response_headers.nil?

      value = header_value(response_headers, "atlas-unknown-fields")
      return if value.nil? || value.strip.empty?

      fields = value.split(",").map(&:strip).reject(&:empty?)
      @on_unknown_fields.call(UnknownFields.new(fields: fields, method: verb, path: path))
    rescue StandardError
      nil
    end

    def header_value(response_headers, name)
      response_headers.each do |key, value|
        next unless key.to_s.downcase == name

        return value.is_a?(Array) ? value.join(",") : value.to_s
      end
      nil
    end

    def join_url(base, path)
      "#{base.sub(%r{/+\z}, '')}#{path.start_with?('/') ? path : "/#{path}"}"
    end

    # Serialize a query hash to a string, dropping nil, spreading arrays,
    # rendering booleans as "true"/"false" — mirroring the TS/Python transports.
    def serialize_query(query)
      return "" if query.nil? || query.empty?

      parts = []
      query.each do |key, value|
        next if value.nil?

        values = value.is_a?(Array) ? value : [value]
        values.each do |v|
          next if v.nil?

          rendered = v == true ? "true" : v == false ? "false" : v.to_s
          parts << "#{encode(key.to_s)}=#{encode(rendered)}"
        end
      end
      parts.empty? ? "" : "?#{parts.join('&')}"
    end

    def encode(str)
      URI.encode_www_form_component(str)
    end

    # Parse a non-2xx body into the §9.1 envelope, or synthesize one, and pick
    # the most specific typed error class for the status.
    def to_api_error(status, text)
      errors = []
      message = nil
      if text && !text.empty?
        begin
          parsed = JSON.parse(text)
          envelope = parsed.is_a?(Hash) ? parsed["errors"] : nil
          if envelope.is_a?(Array) && !envelope.empty?
            errors = envelope
          else
            message = text[0, 500]
          end
        rescue JSON::ParserError
          message = text[0, 500]
        end
      end
      if errors.empty?
        errors = [{ "code" => "UNKNOWN",
                    "message" => message || "Atlas API request failed with status #{status}" }]
      end
      ErrorFactory.build(status, errors)
    end
  end

  # The default requester: percent-encodes nothing extra, follows no redirects,
  # and speaks plain +Net::HTTP+. Kept tiny and dependency-free so the gem runs
  # anywhere stdlib does.
  class NetHTTPRequester
    METHODS = {
      "GET" => Net::HTTP::Get,
      "POST" => Net::HTTP::Post,
      "PATCH" => Net::HTTP::Patch,
      "PUT" => Net::HTTP::Put,
      "DELETE" => Net::HTTP::Delete
    }.freeze

    def initialize(open_timeout: 30, read_timeout: 30)
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    # @return [Array(Integer, String, Hash)] the HTTP status, the raw body text,
    #   and the response headers (lower-cased names).
    def call(method, url, headers, body)
      uri = URI.parse(url)
      klass = METHODS.fetch(method) { raise ArgumentError, "Unsupported HTTP method: #{method}" }

      request = klass.new(uri.request_uri)
      headers.each { |k, v| request[k] = v }
      request.body = body if body

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout

      response = http.request(request)
      response_headers = {}
      response.each_header { |k, v| response_headers[k.downcase] = v }
      [response.code.to_i, response.body.to_s, response_headers]
    end
  end
end
