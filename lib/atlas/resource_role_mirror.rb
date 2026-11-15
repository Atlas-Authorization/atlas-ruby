# frozen_string_literal: true

require "set"

module Atlas
  MirroredResourceType = Struct.new(:key, :inherit, :roles, keyword_init: true)
  MirroredResource = Struct.new(:id, :type, :external_id, :parent_id, keyword_init: true)
  MirroredAssignment = Struct.new(:id, :resource_id, :subject, :role, :inherit, keyword_init: true)

  # +allowed+ is the answer; +grants+ lists what granted it (+resource_id+, +role+, +subject+, +inherited+).
  # +code+ is +nil+, +:unknown_resource+ or +:stale+.
  ResourceRoleCheck = Struct.new(:allowed, :resource_id, :grants, :code, :stale, keyword_init: true) do
    def allowed? = allowed == true
  end

  # In-memory store for the resource-role mirror. A store answers +get_cursor+ / +set_cursor+, +get_type(key)+,
  # +get_resource(ref)+ (+{ id: }+ or +{ type:, external_id: }+), +assignments_on(resource_ids)+, +replace_types(list)+,
  # +replace_resources(list)+, +apply_changes([[:created | :deleted, assignment], ...])+ and optionally
  # +get_last_sync_at+ / +set_last_sync_at+.
  class MemoryResourceRoleMirrorStore
    attr_reader :assignments

    def initialize
      @assignments = {}
      @resources = {}
      @types = {}
      @cursor = nil
      @last_sync_at = nil
    end

    def get_cursor = @cursor
    def set_cursor(cursor) = (@cursor = cursor)
    def get_type(key) = @types[key]
    def get_last_sync_at = @last_sync_at
    def set_last_sync_at(at) = (@last_sync_at = at)
    def replace_types(list) = (@types = list.to_h { |t| [t.key, t] })
    def replace_resources(list) = (@resources = list.to_h { |r| [r.id, r] })

    def get_resource(ref)
      return @resources[ref[:id]] if ref[:id]

      @resources.values.find { |r| r.type == ref[:type] && r.external_id == ref[:external_id] }
    end

    def assignments_on(ids)
      want = ids.to_set
      @assignments.values.select { |a| want.include?(a.resource_id) }
    end

    def apply_changes(changes)
      changes.each do |change, assignment|
        change == :deleted ? @assignments.delete(assignment.id) : @assignments[assignment.id] = assignment
      end
    end
  end

  # A local mirror of resource-role assignments: answer "can this user do X on that resource?" with no network
  # call, following the resource tree and role inheritance exactly as Atlas does. {#sync} loads the resource types
  # and tree and then the ordered +/v1/resource_role_assignments/changes+ feed; {#apply_webhook} applies the
  # +resource_role_assignment.created+ / +.deleted+ events between syncs.
  #
  #   mirror = Atlas::ResourceRoleMirror.for_client(atlas, store: Atlas::MemoryResourceRoleMirrorStore.new)
  #   mirror.sync
  #   mirror.can?({ type: "user", id: "user_1" }, "doc:edit", { type: "doc", external_id: "d1" }, orgs: ["org_1"])
  class ResourceRoleMirror
    MAX_DEPTH = 16

    # @param source [#list_types, #list_resources, #list_changes] where the data comes from (see {.for_client}).
    # @param max_staleness_ms [Integer, nil] answer +:stale+ (denied) when the last completed sync is older.
    # @param serve_stale_for_ms [Integer] grace past +max_staleness_ms+ during which answers are marked +stale+.
    # @param tree_refresh_ms [Integer] re-read the types and tree on {#sync} at most this often (default every sync).
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(store:, source:, max_staleness_ms: nil, serve_stale_for_ms: 0, on_serve_stale: nil, tree_refresh_ms: 0, now: nil)
      @store = store
      @source = source
      @max_staleness_ms = max_staleness_ms
      @serve_stale_for_ms = serve_stale_for_ms
      @on_serve_stale = on_serve_stale
      @tree_refresh_ms = tree_refresh_ms
      @now = now
      @memory_sync_at = nil
      @tree_at = nil
    end

    # A mirror fed by an {Atlas::Client}.
    def self.for_client(client, **options)
      source = Struct.new(:client) do
        def list_types = client.resources.types.list
        def list_resources(query) = client.resources.list(query)

        def list_changes(query)
          client.transport.request(method: :get, path: "/v1/resource_role_assignments/changes", query: query)
        end
      end.new(client)
      new(source: source, **options)
    end

    # Which of +chain+'s assignments grant +permission+ to any of +subjects+. +chain+ lists the resource then its
    # ancestors, each +{ resource_id:, type: { inherit:, roles: }, assignments: [{ subject:, role_key:, inherit: }] }+.
    # An ancestor's assignment applies only when it is inheritable, and the walk stops at a type that does not inherit.
    def self.resolve_grants(chain, subjects, permission)
      held = subjects.to_a
      grants = []
      chain.each_with_index do |link, i|
        link[:assignments].each do |a|
          next if !held.include?(a[:subject]) || (i.positive? && !a[:inherit])

          perms = role_permissions(link[:type][:roles], a[:role_key])
          if perms.include?(permission) || perms.include?("*")
            grants << { resource_id: link[:resource_id], role: a[:role_key], subject: a[:subject], inherited: i.positive? }
          end
        end
        break unless link[:type][:inherit]
      end
      grants
    end

    def self.role_permissions(roles, key, seen = [])
      return [] if seen.include?(key)

      seen << key
      role = roles.find { |r| (r["key"] || r[:key]) == key }
      return [] unless role

      perms = Array(role["permissions"] || role[:permissions]).dup
      Array(role["includes"] || role[:includes]).each { |inc| perms |= role_permissions(roles, inc, seen) }
      perms
    end

    def last_sync_at = @store.respond_to?(:get_last_sync_at) ? @store.get_last_sync_at : @memory_sync_at

    # May +subject+ (+{ type: "user" | "group" | "org", id: }+) do +permission+ on +resource+ (+{ id: }+ or
    # +{ type:, external_id: }+)? +orgs:+ and +groups:+ add the subjects the user acts through.
    # @return [Atlas::ResourceRoleCheck]
    def check(subject, permission, resource, orgs: [], groups: [])
      served_stale = false
      if @max_staleness_ms
        at = last_sync_at
        behind = at.nil? ? Float::INFINITY : now - at - @max_staleness_ms
        if behind.positive?
          return ResourceRoleCheck.new(allowed: false, resource_id: nil, grants: [], code: :stale) if at.nil? || behind > @serve_stale_for_ms

          served_stale = true
          @on_serve_stale&.call(last_sync_at: at, stale_for_ms: behind)
        end
      end
      row = @store.get_resource(resource)
      if row.nil? || !permission.is_a?(String) || permission.empty?
        return ResourceRoleCheck.new(allowed: false, resource_id: row&.id, grants: [], code: row ? nil : :unknown_resource)
      end

      subjects = ["#{subject[:type]}:#{subject[:id]}"] + groups.map { |g| "group:#{g}" } + orgs.map { |o| "org:#{o}" }
      grants = self.class.resolve_grants(chain_of(row), subjects, permission)
      ResourceRoleCheck.new(allowed: !grants.empty?, resource_id: row.id, grants: grants, stale: served_stale ? true : nil)
    end

    def can?(subject, permission, resource, **options) = check(subject, permission, resource, **options).allowed?

    # Refresh from Atlas. @return [Hash] +{ applied: n }+
    def sync
      if @tree_at.nil? || now - @tree_at >= @tree_refresh_ms
        types = Array(@source.list_types["data"]).map { |t| MirroredResourceType.new(key: t["key"], inherit: t["inherit"], roles: t["roles"]) }
        tree = []
        cursor = nil
        loop do
          query = { limit: 1000 }
          query[:starting_after] = cursor if cursor
          page = @source.list_resources(query)
          Array(page["data"]).each { |r| tree << MirroredResource.new(id: r["id"], type: r["type"], external_id: r["external_id"], parent_id: r["parent_id"]) }
          break unless page["has_more"] && page["next_cursor"]

          cursor = page["next_cursor"]
        end
        @store.replace_types(types)
        @store.replace_resources(tree)
        @tree_at = now
      end
      after = @store.get_cursor
      applied = 0
      loop do
        query = { limit: 500 }
        query[:after] = after if after
        page = @source.list_changes(query)
        data = Array(page["data"])
        @store.apply_changes(data.map { |c| [c["change"].to_sym, to_assignment(c)] })
        applied += data.size
        if page["next_cursor"]
          after = page["next_cursor"]
          @store.set_cursor(after)
        end
        next if page["has_more"]

        @memory_sync_at = now
        @store.set_last_sync_at(@memory_sync_at) if @store.respond_to?(:set_last_sync_at)
        return { applied: applied }
      end
    end

    # Apply a +resource_role_assignment.created+ / +.deleted+ webhook event. @return [Boolean]
    def apply_webhook(event)
      type = event.is_a?(Hash) ? event["type"] : nil
      return false unless %w[resource_role_assignment.created resource_role_assignment.deleted].include?(type)

      d = event["data"]
      subject = d.is_a?(Hash) ? d["subject"] : nil
      return false unless d.is_a?(Hash) && d["id"].is_a?(String) && d["resource_id"].is_a?(String) && d["role"].is_a?(String) &&
                          subject.is_a?(Hash) && subject["type"].is_a?(String) && subject["id"].is_a?(String)

      assignment = MirroredAssignment.new(id: d["id"], resource_id: d["resource_id"], subject: "#{subject['type']}:#{subject['id']}",
                                          role: d["role"], inherit: d["inherit"] != false)
      @store.apply_changes([[type.end_with?(".created") ? :created : :deleted, assignment]])
      true
    end

    private

    def now = (@now ? @now.call : (Time.now.to_f * 1000)).to_i

    def to_assignment(change)
      MirroredAssignment.new(id: change["assignment_id"], resource_id: change["resource_id"],
                             subject: "#{change['subject']['type']}:#{change['subject']['id']}", role: change["role"], inherit: change["inherit"])
    end

    def chain_of(resource)
      ancestors = []
      id = resource.parent_id
      MAX_DEPTH.times do
        break unless id

        row = @store.get_resource({ id: id })
        break if row.nil? || ancestors.any? { |r| r.id == row.id }

        ancestors << row
        id = row.parent_id
      end
      rows = [resource] + ancestors
      assignments = @store.assignments_on(rows.map(&:id))
      rows.map do |r|
        t = @store.get_type(r.type)
        { resource_id: r.id, type: { key: r.type, inherit: t ? t.inherit : true, roles: t ? t.roles : [] },
          assignments: assignments.select { |a| a.resource_id == r.id }.map { |a| { subject: a.subject, role_key: a.role, inherit: a.inherit } } }
      end
    end
  end
end
