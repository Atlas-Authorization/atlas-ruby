# frozen_string_literal: true

require "json"
require "base64"
require "net/http"
require "uri"

module Atlas
  # §7.3: "JWKS cached in-process with kid-miss refetch (max 1/min) so key
  # rotation needs no deploys."
  #
  # The rate limit on the refetch is the security property, not a politeness.
  # Without it, an attacker sends tokens carrying random +kid+ values and every
  # one forces an outbound request to the JWKS endpoint — turning any
  # unauthenticated caller into a traffic amplifier. The cache's job is as much
  # to refuse to fetch as it is to fetch.
  class JwksCache
    # §7.3: at most one refetch per minute, however many misses arrive.
    REFETCH_INTERVAL_MS = 60_000
    # §7.3 serves +Cache-Control: max-age=3600+; honoured rather than ignored.
    DEFAULT_TTL_MS = 3_600_000

    # Exposed so a caller can assert the rate limit actually bit.
    # One of :fresh, :cached, :refetched, :throttled, :failed.
    attr_reader :last_outcome

    # @param url [String] the instance JWKS URL.
    # @param fetch_impl [#call] optional +call(url) -> [status, body]+ for tests.
    # @param now [#call] optional clock returning epoch milliseconds.
    def initialize(url:, fetch_impl: nil, now: nil, ttl_ms: DEFAULT_TTL_MS,
                   refetch_interval_ms: REFETCH_INTERVAL_MS)
      @url = url
      @fetch_impl = fetch_impl
      @now = now
      @ttl_ms = ttl_ms
      @refetch_interval_ms = refetch_interval_ms
      @cached = nil
      @fetched_at = 0
      @last_attempt_at = 0
      @last_outcome = :fresh
      @mutex = Mutex.new
    end

    # The JWKS to verify against, refetching if this +kid+ is unknown. Returns
    # whatever is cached when a refetch is throttled or fails — a stale JWKS
    # still verifies every token signed by a key it contains.
    #
    # @return [Hash, nil] a +{ "keys" => [...] }+ hash, or nil if never fetched.
    def get(kid = nil)
      @mutex.synchronize do
        now = current_time
        expired = @cached.nil? || (now - @fetched_at) >= @ttl_ms
        kid_miss = !@cached.nil? && !key?(kid)

        if !expired && !kid_miss
          @last_outcome = :cached
          return @cached
        end

        if kid_miss && !expired && (now - @last_attempt_at) < @refetch_interval_ms
          @last_outcome = :throttled
          return @cached
        end

        @last_attempt_at = now
        begin
          body = fetch_jwks
          raise "JWKS is malformed" unless body.is_a?(Hash) && body["keys"].is_a?(Array)

          @cached = body
          @fetched_at = now
          @last_outcome = kid_miss ? :refetched : :fresh
          @cached
        rescue StandardError
          # Keep serving what we have. A JWKS outage should degrade to "new keys
          # do not work yet", not "nobody can authenticate".
          @last_outcome = :failed
          @cached
        end
      end
    end

    # Test and diagnostic surface — never used for a security decision.
    def snapshot
      { keys: @cached ? @cached["keys"].length : 0, fetched_at: @fetched_at }
    end

    private

    def current_time
      @now ? @now.call : (Time.now.to_f * 1000).to_i
    end

    def key?(kid)
      return false if @cached.nil?
      return !@cached["keys"].empty? if kid.nil?

      @cached["keys"].any? { |k| k["kid"] == kid }
    end

    def fetch_jwks
      if @fetch_impl
        status, text = @fetch_impl.call(@url)
        raise "JWKS fetch failed (#{status})" unless status.between?(200, 299)

        return JSON.parse(text)
      end

      uri = URI.parse(@url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      request = Net::HTTP::Get.new(uri.request_uri)
      request["accept"] = "application/json"
      response = http.request(request)
      raise "JWKS fetch failed (#{response.code})" unless response.code.to_i.between?(200, 299)

      JSON.parse(response.body.to_s)
    end
  end

  # Read the +kid+ from a JWT header without verifying anything.
  def self.read_kid(jwt)
    header = jwt.to_s.split(".").first
    return nil if header.nil? || header.empty?

    decoded = Base64.urlsafe_decode64(pad_base64(header))
    parsed = JSON.parse(decoded)
    parsed["kid"].is_a?(String) ? parsed["kid"] : nil
  rescue StandardError
    nil
  end

  # Base64url strings from JWTs are unpadded; restore padding before decoding.
  def self.pad_base64(str)
    str += "=" * ((4 - (str.length % 4)) % 4)
    str
  end
end
