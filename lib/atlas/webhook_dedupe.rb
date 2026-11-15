# frozen_string_literal: true

require_relative "webhook"

module Atlas
  # Raised by {WebhookDedupe.verify} when a delivery cannot be trusted. +reason+ is a Webhook failure
  # (+:missing_headers+, +:malformed_signature+, +:stale_timestamp+, +:signature_mismatch+) or +:invalid_body+.
  class WebhookVerificationError < Error
    attr_reader :reason

    def initialize(reason)
      @reason = reason
      super("Atlas webhook verification failed: #{reason}")
    end
  end

  # A verified delivery. +duplicate?+ is true when the same +delivery_id+ was already recorded (Atlas retries a
  # delivery with the same id until you answer 2xx). Call +release+ when your handler fails so a retry is processed.
  WebhookDelivery = Struct.new(:event, :duplicate, :delivery_id, :release_proc, keyword_init: true) do
    def duplicate? = duplicate == true
    def release = release_proc&.call
  end

  # In-memory dedupe store (tests, one process). A store answers +set_if_absent(key, ttl_seconds)+ (true when the
  # key was new) and, optionally, +delete(key)+.
  class MemoryWebhookStore
    def initialize(now: nil)
      @seen = {}
      @now = now
      @mutex = Mutex.new
    end

    def set_if_absent(key, ttl_seconds)
      @mutex.synchronize do
        t = (@now ? @now.call : Time.now).to_f
        @seen.delete_if { |_, exp| exp <= t }
        return false if @seen.key?(key)

        @seen[key] = t + ttl_seconds
        true
      end
    end

    def delete(key)
      @mutex.synchronize { @seen.delete(key) }
    end
  end

  # A SQL-backed store over any +query(sql, params)+ callable returning an Array of row Hashes (for +postgres+,
  # +sqlite+ or +mysql+; mysql and sqlite may return the affected row count instead). Table:
  #
  #   create table atlas_webhook_seen (key text primary key, expires_at timestamptz not null);
  class SqlWebhookStore
    def initialize(query:, dialect: :postgres)
      raise ArgumentError, "dialect must be :postgres, :sqlite or :mysql" unless %i[postgres sqlite mysql].include?(dialect)

      @query = query
      @dialect = dialect
    end

    def set_if_absent(key, ttl_seconds)
      case @dialect
      when :sqlite
        now = (Time.now.to_f * 1000).to_i
        rows = @query.call("insert into atlas_webhook_seen (key, expires_at) values (?, ?) " \
                           "on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= ? returning key",
                           [key, now + (ttl_seconds * 1000), now])
        affected(rows).positive?
      when :mysql
        @query.call("delete from atlas_webhook_seen where `key` = ? and expires_at <= now()", [key])
        rows = @query.call("insert ignore into atlas_webhook_seen (`key`, expires_at) values (?, now() + interval ? second)", [key, ttl_seconds.floor])
        affected(rows).positive?
      else
        rows = @query.call("insert into atlas_webhook_seen (key, expires_at) values ($1, now() + ($2 || ' seconds')::interval) " \
                           "on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= now() returning key",
                           [key, ttl_seconds.to_s])
        affected(rows).positive?
      end
    end

    def delete(key)
      sql = { postgres: "delete from atlas_webhook_seen where key = $1", mysql: "delete from atlas_webhook_seen where `key` = ?",
              sqlite: "delete from atlas_webhook_seen where key = ?" }.fetch(@dialect)
      @query.call(sql, [key])
    end

    private

    def affected(result) = result.is_a?(Integer) ? result : Array(result).size
  end

  # Verify an Atlas webhook and drop the retries of a delivery you already handled, in one call.
  #
  #   delivery = Atlas::WebhookDedupe.verify(body: request.raw_post, headers: request.headers, secret: secret, store: store)
  #   return head(:ok) if delivery.duplicate?
  #   begin
  #     handle(delivery.event)
  #   rescue StandardError
  #     delivery.release   # let Atlas's retry through
  #     raise
  #   end
  module WebhookDedupe
    DEFAULT_TTL_SECONDS = 86_400
    DEFAULT_KEY_PREFIX = "atlas-webhook:"

    module_function

    # Atlas delivery (+atlas-id+ / +atlas-signature+). Takes the options of {Atlas::Webhook.verify} plus +store+.
    # @return [Atlas::WebhookDelivery]
    # @raise [Atlas::WebhookVerificationError]
    def verify(store:, ttl_seconds: DEFAULT_TTL_SECONDS, key_prefix: DEFAULT_KEY_PREFIX, **verify_options)
      dedupe(Webhook.verify(**verify_options), store, ttl_seconds, key_prefix)
    end

    # Standard Webhooks delivery (an application webhook: +webhook-id+ / +webhook-signature+).
    def verify_standard(store:, ttl_seconds: DEFAULT_TTL_SECONDS, key_prefix: DEFAULT_KEY_PREFIX, **verify_options)
      dedupe(Webhook.verify_standard(**verify_options), store, ttl_seconds, key_prefix)
    end

    def dedupe(result, store, ttl_seconds, key_prefix)
      raise WebhookVerificationError, (result.reason || :signature_mismatch) if !result.verified? || result.delivery_id.nil?
      raise WebhookVerificationError, :invalid_body if result.event.nil?

      key = "#{key_prefix}#{result.delivery_id}"
      fresh = store.set_if_absent(key, ttl_seconds)
      WebhookDelivery.new(event: result.event, duplicate: !fresh, delivery_id: result.delivery_id,
                          release_proc: -> { store.delete(key) if store.respond_to?(:delete) })
    end
  end
end
