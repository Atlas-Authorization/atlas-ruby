# frozen_string_literal: true

module Atlas
  # Raised by +protect+ when a claims set fails an authorization condition. An
  # app maps this to a 401/403. Mirrors +@atlas/authz+'s +ForbiddenError+.
  class ForbiddenError < Error
    # @return [Symbol] why the check failed (:unauthenticated, :permission, :role, ...).
    attr_reader :reason
    # @return [Hash] the condition that was evaluated.
    attr_reader :condition

    def initialize(reason, condition = {})
      @reason = reason
      @condition = condition
      super("Forbidden: #{reason}")
    end
  end

  # The shared authorization primitive — the Ruby peer of +@atlas/authz+.
  #
  # A condition is a hash; an empty condition means "signed in". Supported keys
  # (string or symbol):
  #   * +:permission+       — the claims must grant this org permission.
  #   * +:role+             — the claims' org role must equal this.
  #   * +:any_permission+   — at least one of these permissions is granted.
  #   * +:all_permissions+  — every one of these permissions is granted.
  module Authorization
    module_function

    # True when the claims satisfy the condition.
    def has_from_claims?(claims, condition = {})
      evaluate(claims, condition)[:allowed]
    end

    # Evaluate a condition, returning +{ allowed:, reason: }+.
    def evaluate(claims, condition = {})
      condition ||= {}
      permission = fetch(condition, :permission)
      role = fetch(condition, :role)
      any_permission = fetch(condition, :any_permission)
      all_permissions = fetch(condition, :all_permissions)

      # Empty condition: signed in is enough.
      if permission.nil? && role.nil? && any_permission.nil? && all_permissions.nil?
        return { allowed: true, reason: nil }
      end

      granted = Array(fetch(claims, :org_permissions))
      org_role = fetch(claims, :org_role)

      return deny(:permission) if permission && !granted.include?(permission)
      return deny(:role) if role && org_role != role
      if any_permission && (Array(any_permission) & granted).empty?
        return deny(:permission)
      end
      if all_permissions && !(Array(all_permissions) - granted).empty?
        return deny(:permission)
      end

      { allowed: true, reason: nil }
    end

    def deny(reason)
      { allowed: false, reason: reason }
    end

    # Look a key up under both its symbol and string form.
    def fetch(hash, key)
      return nil unless hash

      if hash.key?(key)
        hash[key]
      elsif hash.key?(key.to_s)
        hash[key.to_s]
      end
    end
  end
end
