# frozen_string_literal: true

require "digest"
require "ipaddr"

module Atlas
  # What the mirror keeps per end-user API key. Never the secret: only its sha256 (hex). Times are epoch ms.
  MirroredApiKey = Struct.new(:id, :hash_hex, :prefix, :subject_type, :subject_id, :name, :scopes, :allowed_ips,
                              :expires_at, :revoked_at, :organization_id, :revoked_reason, keyword_init: true)

  # The answer of {KeyMirror#verify}. +code+ is +nil+ when valid, otherwise +:insufficient_scope+, +:ip_not_allowed+,
  # +:client_ip_required+, +:membership_unresolved+ or +:stale+.
  KeyVerification = Struct.new(:valid, :key, :effective_scopes, :organization, :stale, :code, :missing_scopes, :last_sync_at,
                               keyword_init: true) do
    def valid? = valid == true
  end

  # In-memory key store (tests, one process). A store answers +put(key)+, +get(id)+, +get_by_hash(hex)+,
  # +mark_revoked(id, revoked_at, reason = nil)+, +get_cursor+ / +set_cursor(c)+ and optionally
  # +mark_membership_ended(user_id, organization_id, revoked_at)+ and +get_last_sync_at+ / +set_last_sync_at(at)+.
  # Back it with a table in production.
  class MemoryKeyMirrorStore
    attr_reader :keys

    def initialize
      @keys = {}
      @cursor = nil
      @last_sync_at = nil
      @mutex = Mutex.new
    end

    def put(key) = @mutex.synchronize { @keys[key.id] = key.dup }
    def get(id) = @mutex.synchronize { @keys[id] }
    def get_by_hash(hex) = @mutex.synchronize { @keys.values.find { |k| k.hash_hex == hex } }
    def get_cursor = @cursor
    def set_cursor(cursor) = (@cursor = cursor)
    def get_last_sync_at = @last_sync_at
    def set_last_sync_at(at) = (@last_sync_at = at)

    def mark_revoked(id, revoked_at, reason = nil)
      @mutex.synchronize do
        key = @keys[id]
        next unless key && key.revoked_at.nil?

        key.revoked_at = revoked_at
        key.revoked_reason = reason if reason
      end
    end

    def mark_membership_ended(user_id, organization_id, revoked_at)
      @mutex.synchronize do
        @keys.each_value do |k|
          next unless k.revoked_at.nil? && k.subject_type == "user" && k.subject_id == user_id && k.organization_id == organization_id

          k.revoked_at = revoked_at
          k.revoked_reason = "membership_ended"
        end
      end
    end
  end

  # A local, authoritative mirror of end-user API keys (+ak_+), with Atlas as the minting and revocation backstop.
  #
  # Your request path verifies a presented key against the LOCAL row (sha256 hash, scopes, expiry, revocation) with
  # no network call. Atlas mints and imports keys and is told about every revoke; a revoke made anywhere else (the
  # dashboard, the user's own key page, another service) reaches the mirror through {#sync} (the
  # +/v1/api_keys/revoked+ feed) or {#apply_webhook} (the +api_key.*+ webhooks). Revoking locally happens FIRST, so a
  # failed Atlas call never leaves a key usable here.
  #
  #   mirror = Atlas::KeyMirror.new(store: store, api_keys: atlas.api_keys, max_staleness_ms: 120_000)
  #   created = mirror.mint({ subject_type: "user", subject_id: "user_1", name: "CI", scopes: ["read"] })
  #   mirror.verify(presented_secret, required_scopes: ["read"], client_ip: request.ip)
  class KeyMirror
    HEX64 = /\A[0-9a-f]{64}\z/

    # @param api_keys [#create, #delete, #list_revoked] +atlas.api_keys+ (also +verify+, +get+, +rotate+ when you use
    #   +verify_at_atlas+ or {#rotate}).
    # @param scope_implications [Hash{String=>Array<String>}] +auth_config.endUserApiKeys.scopeImplications+, so a
    #   local scope check matches Atlas (+"*"+ means every scope).
    # @param allowed_scopes [Array<String>] the instance's scope vocabulary (for +"*"+ implications).
    # @param verify_at_atlas [Boolean] ask Atlas about a key the mirror does not hold (and mirror it).
    # @param max_staleness_ms [Integer, nil] refuse (+:stale+) when the last completed {#sync} is older than this.
    # @param serve_stale_for_ms [Integer] how long past +max_staleness_ms+ a verification is still answered (+stale: true+).
    # @param on_serve_stale [#call, nil] called with +(last_sync_at:, stale_for_ms:)+ while serving stale.
    # @param membership [#call, nil] +(user_id, organization_id) -> { "permissions" => [...] } | nil+: resolves the
    #   CURRENT membership for an organization-bound user key; its scopes are narrowed to those permissions.
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(store:, api_keys:, scope_implications: {}, allowed_scopes: [], verify_at_atlas: false, max_staleness_ms: nil,
                   serve_stale_for_ms: 0, on_serve_stale: nil, membership: nil, now: nil)
      @store = store
      @api_keys = api_keys
      @implications = scope_implications
      @allowed = allowed_scopes
      @verify_at_atlas = verify_at_atlas
      @max_staleness_ms = max_staleness_ms
      @serve_stale_for_ms = serve_stale_for_ms
      @on_serve_stale = on_serve_stale
      @membership = membership
      @now = now
      @memory_sync_at = nil
    end

    # sha256 of the full secret, lowercase hex.
    def self.hash_secret(secret) = Digest::SHA256.hexdigest(secret.to_s)

    # Does +permission+ grant +scope+? Exact, +"*"+, or a +prefix:*+ wildcard.
    def self.permission_covers_scope?(permission, scope)
      permission == scope || permission == "*" || (permission.end_with?(":*") && scope.start_with?(permission[0..-2]))
    end

    # The scopes of +scopes+ that +permissions+ cover, sorted.
    def self.intersect_scopes_with_permissions(scopes, permissions)
      scopes.select { |s| permissions.any? { |p| permission_covers_scope?(p, s) } }.uniq.sort
    end

    # Is +ip+ inside one of the CIDR ranges (a bare address matches itself)?
    def self.ip_in_allowlist?(ip, cidrs)
      addr = IPAddr.new(ip.to_s.strip)
      cidrs.any? do |entry|
        net = IPAddr.new(entry.to_s.strip)
        net.family == addr.family && net.include?(addr)
      rescue IPAddr::Error
        false
      end
    rescue IPAddr::Error
      false
    end

    # Mint a key at Atlas and mirror its hash.
    # @return [Hash] the create answer (it carries the one-time +secret+).
    def mint(body, idempotency_key: nil)
      created = @api_keys.create(body, idempotency_key: idempotency_key)
      @store.put(to_mirrored(created, self.class.hash_secret(created["secret"])))
      created
    end

    # Rotate a key at Atlas and mirror the new one; the old one is dropped now or expires with the overlap.
    def rotate(id, **options)
      raise ArgumentError, "rotate needs an api_keys client with rotate." unless @api_keys.respond_to?(:rotate)

      rotated = @api_keys.rotate(id, **options)
      @store.put(to_mirrored(rotated, self.class.hash_secret(rotated["secret"])))
      old = @store.get(id)
      if old
        previous = rotated["previous_key"] || {}
        if previous["revoked"]
          @store.mark_revoked(id, now, "rotated")
        else
          old.expires_at = previous["expires_at"] || old.expires_at
          @store.put(old)
        end
      end
      rotated
    end

    # Import a key minted elsewhere: +secret:+ (the full secret) or +secret_hash:+ (sha256 hex), or a legacy
    # +bcrypt_hash:+ / +argon2id_hash:+ (verified at Atlas on first use, then mirrored).
    def import(body, secret: nil, secret_hash: nil, bcrypt_hash: nil, argon2id_hash: nil, prefix:, idempotency_key: nil)
      legacy = bcrypt_hash || argon2id_hash
      if legacy
        imported = @api_keys.create(body.merge(import: { secret_hash: legacy, hash_algorithm: bcrypt_hash ? "bcrypt" : "argon2id", prefix: prefix }),
                                    idempotency_key: idempotency_key)
        # No local sha256 yet: verify (with verify_at_atlas) fills it in on first use.
        @store.put(to_mirrored(imported, "legacy:#{imported['id']}")) if imported["outcome"] != "already_present" || @store.get(imported["id"]).nil?
        return imported.merge("outcome" => imported["outcome"] || "created")
      end
      hash = secret_hash&.downcase || (secret && self.class.hash_secret(secret))
      raise ArgumentError, "import needs the full `secret` or its `secret_hash` (64 lowercase hex characters of sha256)." unless hash&.match?(HEX64)

      imported = @api_keys.create(body.merge(import: { secret_hash: hash, hash_algorithm: "sha256_hex", prefix: prefix }), idempotency_key: idempotency_key)
      @store.put(to_mirrored(imported, hash))
      imported.merge("outcome" => imported["outcome"] || "created")
    end

    # Revoke locally first, then at Atlas (a 404 or 409 there is fine: already gone).
    def revoke(id)
      @store.mark_revoked(id, now)
      begin
        @api_keys.delete(id)
      rescue Atlas::APIError => e
        raise unless [404, 409].include?(e.status)
      end
    end

    # Epoch ms of the last completed {#sync}, or nil.
    def last_sync_at = @store.respond_to?(:get_last_sync_at) ? @store.get_last_sync_at : @memory_sync_at

    # Verify a presented secret against the local row.
    # @return [Atlas::KeyVerification]
    def verify(secret, required_scopes: [], client_ip: nil)
      return KeyVerification.new(valid: false) unless secret.is_a?(String) && !secret.empty?

      served_stale = false
      if @max_staleness_ms
        synced = last_sync_at
        behind = synced.nil? ? Float::INFINITY : now - synced - @max_staleness_ms
        if behind.positive?
          return KeyVerification.new(valid: false, code: :stale, last_sync_at: synced) if synced.nil? || behind > @serve_stale_for_ms

          served_stale = true
          @on_serve_stale&.call(last_sync_at: synced, stale_for_ms: behind)
        end
      end
      hash = self.class.hash_secret(secret)
      key = @store.get_by_hash(hash)
      if key.nil? && @verify_at_atlas && @api_keys.respond_to?(:verify) && @api_keys.respond_to?(:get)
        remote = @api_keys.verify(secret)
        if remote["valid"]
          key = to_mirrored(@api_keys.get(remote["id"]), hash)
          @store.put(key)
        end
      end
      return KeyVerification.new(valid: false) if key.nil? || !key.revoked_at.nil?
      return KeyVerification.new(valid: false) if key.expires_at && key.expires_at <= now

      if key.allowed_ips && !key.allowed_ips.empty?
        # A key with allowed_ips needs the end caller's address; no address fails closed.
        return KeyVerification.new(valid: false, code: :client_ip_required) if client_ip.nil? || client_ip.empty?
        return KeyVerification.new(valid: false, code: :ip_not_allowed) unless self.class.ip_in_allowlist?(client_ip, key.allowed_ips)
      end
      effective = expand(key.scopes || [])
      organization = nil
      if key.subject_type == "user" && key.organization_id
        # A bound key stands for the user's CURRENT membership; never answer from the key's own scopes.
        if @membership
          held = @membership.call(key.subject_id, key.organization_id)
          return KeyVerification.new(valid: false) unless held

          organization = held
          effective = self.class.intersect_scopes_with_permissions(effective, held["permissions"] || held[:permissions] || [])
        elsif @api_keys.respond_to?(:verify)
          remote = @api_keys.verify(secret)
          return KeyVerification.new(valid: false) if !remote["valid"] || !remote["organization"]

          organization = remote["organization"]
          effective = remote["effective_scopes"] || []
        else
          return KeyVerification.new(valid: false, code: :membership_unresolved)
        end
      end
      missing = Array(required_scopes).reject { |s| effective.include?(s) }
      return KeyVerification.new(valid: false, code: :insufficient_scope, missing_scopes: missing) unless missing.empty?

      KeyVerification.new(valid: true, key: key, effective_scopes: effective, organization: organization, stale: served_stale ? true : nil)
    end

    # Pull the revocation feed and apply it. @return [Hash] +{ revoked: n }+
    def sync
      since = @store.get_cursor
      revoked = 0
      loop do
        params = { limit: 100 }
        params[:since] = since if since
        page = @api_keys.list_revoked(params)
        Array(page["data"]).each do |ref|
          @store.mark_revoked(ref["id"], ref["revoked_at"] || now, ref["revoked_reason"])
          revoked += 1
        end
        if page["next_cursor"]
          since = page["next_cursor"]
          @store.set_cursor(since)
        end
        next if page["has_more"] && page["next_cursor"]

        @memory_sync_at = now
        @store.set_last_sync_at(@memory_sync_at) if @store.respond_to?(:set_last_sync_at)
        return { revoked: revoked }
      end
    end

    # Apply an +api_key.*+ (or +organization_membership.deleted+) webhook event. @return [Boolean] whether it changed anything.
    def apply_webhook(event)
      type = event.is_a?(Hash) ? event["type"] : nil
      data = event.is_a?(Hash) ? event["data"] : nil
      # A member removed from an organization: drop the keys bound to that membership at once.
      if %w[organization_membership.deleted organizationMembership.deleted].include?(type)
        return false unless data.is_a?(Hash) && data["user_id"].is_a?(String) && data["organization_id"].is_a?(String) && @store.respond_to?(:mark_membership_ended)

        @store.mark_membership_ended(data["user_id"], data["organization_id"], now)
        return true
      end
      return false unless type.is_a?(String) && type.start_with?("api_key.") && data.is_a?(Hash) && data["id"].is_a?(String)

      held = @store.get(data["id"])
      return false unless held

      # A key a ban had suspended works again: lift the local revocation.
      if type == "api_key.restored"
        return false if held.revoked_at.nil?

        held.revoked_at = nil
        held.revoked_reason = nil
        held.expires_at = data["expires_at"] if data.key?("expires_at")
        @store.put(held)
        return true
      end
      if type == "api_key.revoked" || (data["revoked_at"].is_a?(Numeric) && held.revoked_at.nil?)
        @store.mark_revoked(held.id, data["revoked_at"].is_a?(Numeric) ? data["revoked_at"] : now, data["revoked_reason"])
        return true
      end
      if %w[api_key.updated api_key.created].include?(type)
        held.name = data["name"] if data.key?("name")
        held.scopes = data["scopes"] if data.key?("scopes")
        held.allowed_ips = data["allowed_ips"] if data.key?("allowed_ips")
        held.expires_at = data["expires_at"] if data.key?("expires_at")
        @store.put(held)
        return true
      end
      false
    end

    private

    def now = (@now ? @now.call : (Time.now.to_f * 1000)).to_i

    # Held scopes plus everything they imply (+"*"+ implies the whole vocabulary), sorted.
    def expand(held)
      vocab = @allowed.dup
      @implications.each do |from, tos|
        vocab << from
        tos.each { |t| vocab << t unless t == "*" }
      end
      out = held.dup
      queue = held.dup
      until queue.empty?
        (@implications[queue.pop] || []).each do |to|
          (to == "*" ? vocab : [to]).each do |t|
            next if out.include?(t)

            out << t
            queue << t
          end
        end
      end
      out.uniq.sort
    end

    def to_mirrored(key, hash)
      MirroredApiKey.new(id: key["id"], hash_hex: hash, prefix: key["prefix"], subject_type: key["subject_type"],
                         subject_id: key["subject_id"], name: key["name"], scopes: key["scopes"], allowed_ips: key["allowed_ips"],
                         expires_at: key["expires_at"], revoked_at: key["revoked_at"], organization_id: key["organization_id"],
                         revoked_reason: key["revoked_reason"])
    end
  end
end
