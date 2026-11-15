# frozen_string_literal: true

require "json"
require "uri"
require_relative "error"
require_relative "transport"

module Atlas
  # The OAuth 2.0 Device Authorization Grant (RFC 8628) from the device side: a CLI, TV or console shows the user a
  # code, the user approves it in a browser, and the device polls for tokens. (The signed-in user's side is
  # {Atlas::DeviceAuthorizations}.)
  #
  #   start = Atlas::DeviceFlow.start(issuer: "https://auth.example.com", client_id: "cli_1", scope: %w[openid profile])
  #   puts "Open #{start.verification_uri_complete} and confirm #{start.user_code}"
  #   tokens = Atlas::DeviceFlow.poll(start)          # blocks until approved, denied or expired
  module DeviceFlow
    # A refused step. +error+ is the OAuth error (+access_denied+, +expired_token+, +aborted+, ...).
    class Error < Atlas::Error
      attr_reader :error, :status

      def initialize(error, message, status)
        super(message)
        @error = error
        @status = status
      end
    end

    Authorization = Struct.new(:device_code, :user_code, :verification_uri, :verification_uri_complete, :expires_in, :interval,
                               :config, keyword_init: true)
    Endpoints = Struct.new(:device_authorization_endpoint, :token_endpoint, :client_id, :client_secret, keyword_init: true)

    module_function

    # Ask the issuer for a device code.
    # @return [Authorization]
    def start(issuer:, client_id:, client_secret: nil, scope: nil, resource: nil, http: nil)
      base = issuer.to_s.sub(%r{/+\z}, "")
      config = Endpoints.new(device_authorization_endpoint: "#{base}/oauth2/device_authorization", token_endpoint: "#{base}/oauth2/token",
                             client_id: client_id, client_secret: client_secret)
      scope = scope.join(" ") if scope.is_a?(Array)
      form = [["client_id", client_id]]
      form << ["client_secret", client_secret] if client_secret
      form << ["scope", scope] if scope && !scope.empty?
      form << ["resource", resource] if resource
      status, out = post(http, config.device_authorization_endpoint, form)
      raise Error.new((out["error"] || "error").to_s, (out["error_description"] || "Device authorization failed.").to_s, status) unless status == 200

      Authorization.new(device_code: out["device_code"], user_code: out["user_code"], verification_uri: out["verification_uri"],
                        verification_uri_complete: out["verification_uri_complete"], expires_in: out["expires_in"].to_i,
                        interval: out["interval"].to_i, config: config)
    end

    # Poll the token endpoint until the user approves. Waits +interval+ seconds between tries, adds 5 on +slow_down+.
    # @param sleeper [#call, nil] replaces +sleep+ (tests); @param cancelled [#call, nil] returns true to stop.
    # @return [Hash] the token response (+access_token+, +id_token+, +refresh_token+, ...).
    def poll(authorization, http: nil, sleeper: nil, cancelled: nil, now: nil)
      interval = [authorization.interval, 1].max
      clock = now || -> { Time.now.to_f }
      deadline = clock.call + authorization.expires_in
      while clock.call < deadline
        raise Error.new("aborted", "Sign-in was cancelled.", 0) if cancelled&.call

        sleeper ? sleeper.call(interval) : sleep(interval)
        cfg = authorization.config
        form = [["grant_type", "urn:ietf:params:oauth:grant-type:device_code"], ["device_code", authorization.device_code], ["client_id", cfg.client_id]]
        form << ["client_secret", cfg.client_secret] if cfg.client_secret
        status, out = post(http, cfg.token_endpoint, form)
        return out if status == 200
        next if out["error"] == "authorization_pending"

        if out["error"] == "slow_down"
          interval += 5
          next
        end
        raise Error.new((out["error"] || "error").to_s, (out["error_description"] || "Sign-in failed.").to_s, status)
      end
      raise Error.new("expired_token", "The sign-in code expired. Run the login again.", 400)
    end

    def post(http, url, form)
      status, text, = (http || NetHTTPRequester.new).call("POST", url, { "content-type" => "application/x-www-form-urlencoded", "accept" => "application/json" },
                                                          URI.encode_www_form(form))
      json = begin
        JSON.parse(text.to_s)
      rescue JSON::ParserError
        {}
      end
      [status, json.is_a?(Hash) ? json : {}]
    end
    private_class_method :post
  end
end
