# frozen_string_literal: true

require "uri"

module Atlas
  module RP
    # A framework-neutral view of an incoming request: just what the relying party reads.
    # Build one from a Rack env with {Request.from_rack}, or by hand in a test.
    class Request
      attr_reader :method, :url, :headers, :body

      # @param headers [Hash] header names are matched case-insensitively.
      def initialize(method:, url:, headers: {}, body: nil)
        @method = method.to_s.upcase
        @url = url
        @headers = headers.transform_keys { |k| k.to_s.downcase }
        @body = body
      end

      def self.from_rack(env)
        scheme = env["HTTP_X_FORWARDED_PROTO"]&.split(",")&.first&.strip || env["rack.url_scheme"] || "http"
        host = env["HTTP_X_FORWARDED_HOST"] || env["HTTP_HOST"] || "#{env['SERVER_NAME']}:#{env['SERVER_PORT']}"
        path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
        query = env["QUERY_STRING"].to_s
        headers = env.each_with_object({}) do |(k, v), h|
          h[k.sub(/\AHTTP_/, "").tr("_", "-").downcase] = v if k.start_with?("HTTP_") && v.is_a?(String)
        end
        headers["content-type"] = env["CONTENT_TYPE"] if env["CONTENT_TYPE"]
        new(method: env["REQUEST_METHOD"], url: "#{scheme}://#{host}#{path}#{query.empty? ? '' : "?#{query}"}",
            headers: headers, body: -> { read_body(env) })
      end

      def self.read_body(env)
        input = env["rack.input"]
        return "" unless input

        input.rewind if input.respond_to?(:rewind)
        data = input.read.to_s
        input.rewind if input.respond_to?(:rewind)
        data
      end

      def uri = @uri ||= URI.parse(url)
      def path = uri.path.to_s.empty? ? "/" : uri.path
      def path_and_query = uri.query ? "#{path}?#{uri.query}" : path
      def header(name) = headers[name.to_s.downcase]
      def cookie_header = header("cookie")

      # The query parameters (first value wins).
      def query
        URI.decode_www_form(uri.query.to_s).each_with_object({}) { |(k, v), h| h[k] ||= v }
      end

      # The form-encoded body's parameters (first value wins).
      def form
        raw = body.respond_to?(:call) ? body.call : body
        URI.decode_www_form(raw.to_s).each_with_object({}) { |(k, v), h| h[k] ||= v }
      end
    end

    # What the relying party answers with. +cookies+ are +Set-Cookie+ values; {#to_rack} renders it.
    class Response
      attr_accessor :status, :headers, :body, :cookies

      def initialize(status:, headers: {}, body: "", cookies: [])
        @status = status
        @headers = headers
        @body = body
        @cookies = cookies.dup
      end

      def self.redirect(location, cookies = [])
        new(status: 302, headers: { "location" => location, "cache-control" => "no-store" }, cookies: cookies)
      end

      def self.text(status, text, extra = {})
        new(status: status, headers: { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }.merge(extra), body: text)
      end

      def add_cookie(cookie)
        @cookies << cookie if cookie
        self
      end

      def location = headers["location"]

      # @return [Array(Integer, Hash, Array)] a Rack response triple.
      def to_rack
        out = headers.dup
        Response.merge_cookies(out, cookies)
        [status, out, [body.to_s]]
      end

      # Add +Set-Cookie+ values to a Rack headers Hash (an Array under Rack 3, newline-joined under Rack 2).
      def self.merge_cookies(headers, cookies)
        return headers if cookies.empty?

        key = headers.keys.find { |k| k.to_s.casecmp?("set-cookie") } || "set-cookie"
        existing = headers[key]
        all = (existing.nil? ? [] : existing.is_a?(Array) ? existing : existing.to_s.split("\n")) + cookies
        headers[key] = rack3? ? all : all.join("\n")
        headers
      end

      def self.rack3?
        defined?(::Rack::RELEASE) && Gem::Version.new(::Rack::RELEASE) >= Gem::Version.new("3")
      rescue ArgumentError
        false
      end
    end
  end
end
