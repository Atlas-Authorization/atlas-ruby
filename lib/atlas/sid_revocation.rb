# frozen_string_literal: true

require_relative "transport"
require_relative "status_list"

module Atlas
  # A local deny-list of revoked Atlas session ids (+sid+), kept fresh by polling +GET /v1/sessions/revoked+.
  # Verify tokens offline with {Atlas::Backend} and ask this list whether the token's +sid+ was revoked since it
  # was issued: revocation takes effect within the poll interval, with no network call on the request path.
  #
  #   revoked = Atlas::SidRevocationList.new(secret_key: ENV["ATLAS_SECRET_KEY"], on_stale: :reject)
  #   result = backend.verify(token)
  #   deny! if result.ok? && (revoked.unavailable? || revoked.revoked?(result.claims["sid"]))
  #
  # With +source: :status_list+ (needs +jwks_url+, and +issuer+ to pin the signer) the check uses the signed status
  # list (+/v1/sessions/revocations/status-list+, verified offline) and falls back to the feed above whenever the
  # list cannot answer (no list yet, or truncated and the sid not named).
  #
  # An entry is kept for +max_token_lifetime_seconds+ after the revocation (a token cannot outlive it), then
  # dropped. With +on_stale: :reject+, {#unavailable?} turns true once the list could not be refreshed for
  # +stale_after_ms+ (plus +serve_stale_for_ms+), so a caller fails closed rather than trust an old list.
  class SidRevocationList
    # @param secret_key [String] a secret key with +sessions:read+.
    # @param interval_ms [Integer] minimum time between polls (default 15 s).
    # @param max_token_lifetime_seconds [Integer] default 3600.
    # @param on_stale [Symbol] +:allow+ (default) or +:reject+.
    # @param stale_after_ms [Integer] default 120 s.
    # @param serve_stale_for_ms [Integer] how long past +stale_after_ms+ the last list is still served.
    # @param on_serve_stale [#call, nil] called with +(last_success_at:, stale_for_ms:)+ while serving stale.
    # @param on_error [#call, nil] called with the exception of a failed poll.
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(secret_key:, api_url: DEFAULT_API_URL, http: nil, interval_ms: 15_000, max_token_lifetime_seconds: 3600,
                   on_stale: :allow, stale_after_ms: 120_000, serve_stale_for_ms: 0, on_serve_stale: nil, on_error: nil, now: nil,
                   source: :feed, jwks_url: nil, issuer: nil)
      raise ArgumentError, "on_stale must be :allow or :reject" unless %i[allow reject].include?(on_stale)
      raise ArgumentError, "source must be :feed or :status_list" unless %i[feed status_list].include?(source)
      raise ArgumentError, "source :status_list needs jwks_url" if source == :status_list && jwks_url.nil?

      @transport = Transport.new(secret_key: secret_key, api_url: api_url, http: http)
      @interval_ms = interval_ms
      @lifetime_ms = max_token_lifetime_seconds * 1000
      @on_stale = on_stale
      @stale_after_ms = stale_after_ms
      @serve_stale_for_ms = serve_stale_for_ms
      @on_serve_stale = on_serve_stale
      @on_error = on_error
      @now = now
      @revoked = {}
      @since = nil
      @next_poll_at = 0
      @last_success_at = nil
      @created_at = clock
      @mutex = Mutex.new
      @checker = source == :status_list &&
                 StatusList::EdgeChecker.new(secret_key: secret_key, api_url: api_url, jwks_url: jwks_url, issuer: issuer, http: http,
                                             window_seconds: [86_400, [60, (@lifetime_ms / 1000.0).ceil].max].min, refresh_ms: interval_ms,
                                             stale_after_ms: stale_after_ms, on_stale: :allow, now: now,
                                             on_error: ->(e) { @on_error&.call(e) })
    end

    # True when the list is too stale to trust (only with +on_stale: :reject+).
    def unavailable?
      return false unless @on_stale == :reject

      stale = clock - (@last_success_at || @created_at) - @stale_after_ms
      return false if stale <= 0

      if @last_success_at && stale <= @serve_stale_for_ms
        @on_serve_stale&.call(last_success_at: @last_success_at, stale_for_ms: stale)
        return false
      end
      true
    end

    # True when +sid+ was revoked (and its tokens could still be live). Polls first when the interval has passed.
    def revoked?(sid)
      return false if sid.nil?

      if @checker
        verdict = @checker.check(sid)
        @last_success_at = @checker.last_success_at
        return verdict == :revoked unless verdict == :unavailable
      end
      @mutex.synchronize do
        poll if clock >= @next_poll_at
        expiry = @revoked[sid]
        !expiry.nil? && expiry > clock
      end
    end

    # Epoch ms of the last successful refresh, or nil.
    attr_reader :last_success_at

    private

    def clock = (@now ? @now.call : (Time.now.to_f * 1000)).to_i

    def poll
      started = clock
      @next_poll_at = started + @interval_ms
      cursor = nil
      server_time = started
      loop do
        query = { since: @since || (started - @lifetime_ms), limit: 5000 }
        query[:cursor] = cursor if cursor
        page = @transport.request(method: :get, path: "/v1/sessions/revoked", query: query)
        Array(page["data"]).each { |r| @revoked[r["sid"]] = r["revoked_at"].to_i + @lifetime_ms }
        server_time = page["server_time"].to_i if page["server_time"]
        cursor = page["has_more"] && page["next_cursor"] ? page["next_cursor"] : nil
        break unless cursor
      end
      @since = server_time - 10_000
      @last_success_at = started
      @revoked.delete_if { |_, expiry| expiry <= started }
    rescue StandardError => e
      @on_error&.call(e)
    end
  end
end
