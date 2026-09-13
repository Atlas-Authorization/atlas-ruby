# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

require_relative "error"

module Atlas
  # The default BAPI origin, overridable per instance via +api_url+.
  DEFAULT_API_URL = "https://api.atlas.dev"

  # The shared HTTP core every resource namespace calls.
  #
  # One place decides how a BAPI request is authenticated, serialized, and how a
  # failure becomes an {Atlas::APIError} — so a namespace method is a one-liner
  # naming a method, a path, and its shapes.
  #
  # The HTTP mechanism is injectable: pass +http:+ any object responding to
  # +call(method, url, headers, body)+ and returning +[status_integer,
  # body_string]+. Tests use this to run with no network; the default is a
  # {Atlas::NetHTTPRequester} built on Ruby's stdlib +Net::HTTP+.
  class Transport
    # Sentinel meaning "no body key was supplied", distinct from an explicit
    # empty hash (which is serialized to +{}+ with a content-type, matching the
    # TypeScript SDK's +body !== undefined+ gate).
    OMIT = :__atlas_omit__

    def initialize(secret_key:, api_url: DEFAULT_API_URL, http: nil,
                   open_timeout: 30, read_timeout: 30)
      raise ConfigurationError, "Atlas::Client requires a secret_key." if secret_key.nil? || secret_key.empty?

      @secret_key = secret_key
      @base = api_url || DEFAULT_API_URL
      @http = http || NetHTTPRequester.new(open_timeout: open_timeout, read_timeout: read_timeout)
    end

    # Perform a request and return the parsed JSON (a Hash/Array), the raw text
    # when +raw:+ is true, or +nil+ for an empty/204 body.
    #
    # @raise [Atlas::APIError] on any non-2xx response.
    def request(method:, path:, query: nil, body: OMIT, idempotency_key: nil, raw: false)
      url = join_url(@base, path) + serialize_query(query)

      headers = {
        "authorization" => "Bearer #{@secret_key}",
        "accept" => "application/json"
      }

      payload = nil
      unless body.equal?(OMIT)
        headers["content-type"] = "application/json"
        payload = JSON.generate(body)
      end
      headers["idempotency-key"] = idempotency_key if idempotency_key

      status, text = @http.call(method.to_s.upcase, url, headers, payload)

      raise to_api_error(status, text) unless status.between?(200, 299)

      return nil if status == 204 || text.nil? || text.empty?
      return text if raw

      JSON.parse(text)
    end

    private

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

    # @return [Array(Integer, String)] the HTTP status and the raw body text.
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
      [response.code.to_i, response.body.to_s]
    end
  end
end
