# frozen_string_literal: true

require "json"
require "time"
require "uri"

module Atlas
  # A self-check for a new or misbehaving setup: the secret key, clock skew, JWKS reachability, instance status and
  # configuration. It never raises for a failed check; read the report.
  #
  #   report = atlas.doctor(jwks_url: "https://auth.example.com/v1/jwks", issuer: "https://auth.example.com")
  #   puts report            # one line per check
  #   exit(1) unless report.ok?
  module Doctor
    Check = Struct.new(:name, :status, :detail, keyword_init: true)

    Report = Struct.new(:checks, keyword_init: true) do
      # False when any check failed (warnings do not fail).
      def ok? = checks.none? { |c| c.status == :fail }
      def failures = checks.select { |c| c.status == :fail }
      def to_s = checks.map { |c| format("%-5s %-14s %s", c.status.to_s.upcase, c.name, c.detail) }.join("\n")
    end

    CLOCK_WARN_SECONDS = 5
    CLOCK_FAIL_SECONDS = 60

    module_function

    # @param client [Atlas::Client]
    # @param jwks_url [String, nil] the instance JWKS URL, to check it is reachable and serves keys.
    # @param issuer [String, nil] the expected issuer, checked against +jwks_url+ and for https.
    # @return [Atlas::Doctor::Report]
    def run(client, jwks_url: nil, issuer: nil)
      transport = client.transport
      base = transport.instance_variable_get(:@base)
      http = transport.instance_variable_get(:@http)
      key = transport.instance_variable_get(:@secret_key).to_s
      checks = [check_key(key), *check_status(http, base), check_jwks(http, jwks_url), check_config(base, jwks_url, issuer)].compact
      checks << check_api(client)
      Report.new(checks: checks.compact)
    end

    def check_key(key)
      if key.start_with?("sk_live_") then Check.new(name: "secret key", status: :ok, detail: "live key")
      elsif key.start_with?("sk_test_") then Check.new(name: "secret key", status: :ok, detail: "test key")
      elsif key.start_with?("sk_") then Check.new(name: "secret key", status: :warn, detail: "starts with sk_ but not sk_live_ or sk_test_")
      else Check.new(name: "secret key", status: :fail, detail: "does not look like a secret key (sk_...); never use a publishable key here")
      end
    end

    # The status endpoint, and the clock skew from its Date header.
    def check_status(http, base)
      st, body, headers = http.call("GET", "#{base.sub(%r{/+\z}, '')}/v1/status", { "accept" => "application/json" }, nil)
      return [Check.new(name: "instance status", status: :warn, detail: "status endpoint answered #{st}")] unless st.between?(200, 299)

      doc = JSON.parse(body)
      level = doc["status"].to_s
      bad = level == "major_outage" || Array(doc["components"]).any? { |c| c["id"] == "backend_api" && c["status"] == "major_outage" }
      out = [Check.new(name: "instance status", status: bad ? :fail : (level == "operational" ? :ok : :warn), detail: level.empty? ? "unknown" : level)]
      date = (headers || {}).find { |k, _| k.to_s.downcase == "date" }&.last
      if date
        skew = (Time.httpdate(date) - Time.now).abs
        out << Check.new(name: "clock skew", status: skew > CLOCK_FAIL_SECONDS ? :fail : (skew > CLOCK_WARN_SECONDS ? :warn : :ok),
                         detail: "#{skew.round(1)}s from Atlas (token checks tolerate about #{CLOCK_WARN_SECONDS}s)")
      end
      out
    rescue StandardError => e
      [Check.new(name: "instance status", status: :warn, detail: "could not read the status endpoint: #{e.message}")]
    end

    def check_jwks(http, jwks_url)
      return nil unless jwks_url

      st, body, = http.call("GET", jwks_url, { "accept" => "application/json" }, nil)
      return Check.new(name: "jwks", status: :fail, detail: "#{jwks_url} answered #{st}") unless st.between?(200, 299)

      n = Array(JSON.parse(body)["keys"]).size
      Check.new(name: "jwks", status: n.positive? ? :ok : :fail, detail: "#{n} signing key#{'s' unless n == 1} at #{jwks_url}")
    rescue StandardError => e
      Check.new(name: "jwks", status: :fail, detail: "#{jwks_url} unreachable: #{e.message}")
    end

    def check_config(base, jwks_url, issuer)
      problems = []
      problems << "api_url #{base} is not https" unless base.to_s.start_with?("https://") || base.to_s.match?(%r{\Ahttp://(localhost|127\.0\.0\.1)})
      if issuer
        problems << "issuer #{issuer} is not https" unless issuer.start_with?("https://")
        problems << "issuer host differs from the JWKS host" if jwks_url && URI.parse(issuer).host != URI.parse(jwks_url).host
      end
      problems.empty? ? Check.new(name: "config", status: :ok, detail: "api_url#{issuer ? ', issuer' : ''} look right") : Check.new(name: "config", status: :warn, detail: problems.join("; "))
    rescue URI::InvalidURIError => e
      Check.new(name: "config", status: :fail, detail: e.message)
    end

    # The key authenticates: a cheap authenticated read.
    def check_api(client)
      client.instance.get
      Check.new(name: "api access", status: :ok, detail: "the secret key is accepted")
    rescue Atlas::APIError => e
      Check.new(name: "api access", status: :fail, detail: "#{e.status} #{e.code}: #{e.message}")
    rescue StandardError => e
      Check.new(name: "api access", status: :fail, detail: e.message)
    end
  end
end
