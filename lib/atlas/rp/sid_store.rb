# frozen_string_literal: true

module Atlas
  # Where a relying party records which of your app sessions each Atlas +sid+ backs, so a back-channel
  # logout can end them. A store answers +bind(sid, app_session_id, expires_at)+ (+expires_at+: epoch seconds or
  # Time) and +take(sid)+ (the live app session ids, removed from the store).
  #
  # In-memory, for tests and a single process. With several processes back it with a shared table or Redis
  # (+SADD+ / +EXPIRE+, and +SMEMBERS+ + +DEL+ for +take+).
  class MemorySidStore
    def initialize(now: nil)
      @by_sid = Hash.new { |h, k| h[k] = {} }
      @now = now
      @mutex = Mutex.new
    end

    def bind(sid, app_session_id, expires_at)
      @mutex.synchronize do
        sweep
        @by_sid[sid][app_session_id] = expires_at.to_i
      end
    end

    def take(sid)
      @mutex.synchronize do
        sweep
        (@by_sid.delete(sid) || {}).keys
      end
    end

    private

    def sweep
      t = (@now ? @now.call : Time.now).to_i
      @by_sid.each_value { |apps| apps.delete_if { |_, exp| exp <= t } }
      @by_sid.delete_if { |_, apps| apps.empty? }
    end
  end

  # A SQL-backed store over any +query(sql, params) -> Array<Hash>+ callable (PostgreSQL placeholders). Table:
  #
  #   create table atlas_rp_sessions (
  #     sid text not null, app_session_id text not null, expires_at timestamptz not null,
  #     primary key (sid, app_session_id)
  #   );
  class SqlSidStore
    def initialize(query:)
      @query = query
    end

    def bind(sid, app_session_id, expires_at)
      @query.call("insert into atlas_rp_sessions (sid, app_session_id, expires_at) values ($1, $2, $3) " \
                  "on conflict (sid, app_session_id) do update set expires_at = excluded.expires_at",
                  [sid, app_session_id, Time.at(expires_at.to_i).utc])
    end

    def take(sid)
      rows = @query.call("delete from atlas_rp_sessions where sid = $1 returning app_session_id, expires_at > now() as live", [sid])
      rows.select { |r| r["live"] == true || r["live"] == "t" }.map { |r| r["app_session_id"].to_s }
    end
  end
end
