# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module Atlas
  # Device sign-in approval (OAuth 2.0 Device Authorization Grant, RFC 8628)
  # from your own app: the signed-in user types — or scans — the code a TV,
  # console or CLI shows, and your app approves it instead of sending them to
  # Atlas's hosted +/oauth2/device+ page.
  #
  # These calls run on the Frontend API as the signed-in USER: they need the
  # user's session token (a native app's session JWT), never a secret key, PAT
  # or OAuth token.
  #
  #   devices = Atlas::DeviceAuthorizations.new(frontend_api: "https://clerk.example.com", session_token: jwt)
  #   auth = devices.lookup(typed_code)
  #   devices.approve(auth) # or devices.deny(auth)
  class DeviceAuthorizations
    BASE = "/v1/client/me/device_authorizations"

    # A refused request; +code+ is the server's stable error code (+NOT_FOUND+,
    # +RATE_LIMITED+, +STEP_UP_REQUIRED+, …).
    class Error < StandardError
      attr_reader :status, :code, :param, :reason

      def initialize(status, code, message, param = nil, reason = nil)
        super(message)
        @status = status
        @code = code
        @param = param
        @reason = reason
      end

      # Approving needs a fresh re-authentication first.
      def needs_reverification?
        code == "STEP_UP_REQUIRED"
      end

      # The code is unknown, expired or already used.
      def invalid_code?
        [404, 409].include?(status)
      end
    end

    # Normalise what a person typed into the +XXXX-XXXX+ form devices show.
    def self.format_user_code(value)
      cleaned = value.to_s.upcase.gsub(/[^A-Z0-9]/, "")
      cleaned.length == 8 ? "#{cleaned[0, 4]}-#{cleaned[4, 4]}" : value.to_s.strip
    end

    # The +user_code+ of a verification URL the device displayed, formatted.
    def self.user_code_from_url(url)
      uri = URI.parse(url.to_s)
      return nil if uri.scheme.nil? || uri.query.nil?

      value = URI.decode_www_form(uri.query).to_h["user_code"]
      value.nil? || value.empty? ? nil : format_user_code(value)
    rescue URI::InvalidURIError
      nil
    end

    # @param post_impl [#call, nil] +(url, json_body, headers) -> [status, body]+ (tests).
    def initialize(frontend_api:, session_token:, publishable_key: nil, post_impl: nil)
      @base = frontend_api.sub(%r{/+\z}, "")
      @token = session_token
      @pk = publishable_key
      @post_impl = post_impl
    end

    # Find a pending device sign-in by the code the device shows.
    def lookup(user_code)
      call("#{BASE}/lookup", { user_code: self.class.format_user_code(user_code) })
    end

    # Approve for the signed-in user; the device's next poll receives its tokens.
    def approve(authorization)
      call("#{BASE}/#{URI.encode_www_form_component(authorization['id'])}/approve",
           { user_code: authorization["user_code"] })
    end

    # Deny; the device's next poll is told +access_denied+.
    def deny(authorization)
      call("#{BASE}/#{URI.encode_www_form_component(authorization['id'])}/deny",
           { user_code: authorization["user_code"] })
    end

    private

    def call(path, body)
      headers = { "Authorization" => "Bearer #{@token}", "Accept" => "application/json",
                  "Content-Type" => "application/json" }
      headers["x-publishable-key"] = @pk if @pk
      status, raw = post(@base + path, JSON.generate(body), headers)
      data = begin
        JSON.parse(raw.to_s)
      rescue JSON::ParserError
        nil
      end
      unless status.between?(200, 299)
        first = data.is_a?(Hash) && data["errors"].is_a?(Array) ? (data["errors"].first || {}) : {}
        raise Error.new(status, first["code"] || "UNKNOWN", first["message"] || "The request failed.",
                        first["param"], first["reason"])
      end
      data.is_a?(Hash) ? data : {}
    end

    def post(url, json, headers)
      return @post_impl.call(url, json, headers) if @post_impl

      uri = URI(url)
      req = Net::HTTP::Post.new(uri)
      headers.each { |k, v| req[k] = v }
      req.body = json
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: 10,
                                                read_timeout: 10) { |http| http.request(req) }
      [res.code.to_i, res.body]
    end
  end
end
