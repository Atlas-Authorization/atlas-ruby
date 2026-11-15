# frozen_string_literal: true

module Atlas
  # Step-up and MFA checks on verified session or ID-token claims (a Hash, string or symbol keys).
  #
  #   Atlas.authenticated_within(claims, 300)   # signed in (or re-confirmed) in the last 5 minutes
  #   Atlas.used_multi_factor(claims)           # this sign-in used a second factor
  #   Atlas.mfa_satisfied(claims)               # the account's MFA requirement is met
  module_function

  # True when +auth_time+ (epoch seconds) is within +max_age_seconds+ of now. A claim set with no
  # +auth_time+ is never recent: the check fails closed.
  def authenticated_within(claims, max_age_seconds, now: nil)
    at = claim(claims, "auth_time")
    return false unless at.is_a?(Numeric) && at.finite?

    now_seconds = (now || Time.now).to_f
    now_seconds - at <= max_age_seconds
  end

  # True when this sign-in used a second factor (+acr+ +urn:atlas:acr:mfa+ or +amr+ containing +mfa+).
  def used_multi_factor(claims)
    return true if claim(claims, "acr") == "urn:atlas:acr:mfa"

    amr = claim(claims, "amr")
    amr.is_a?(Array) && amr.include?("mfa")
  end

  # True when the MFA requirement is met: the +mfa_satisfied+ claim when present, otherwise a second factor
  # was used, +mfa+ is true, or the user came through an enterprise SSO connection (the IdP enforces it).
  def mfa_satisfied(claims)
    flag = claim(claims, "mfa_satisfied")
    return flag if flag == true || flag == false

    claim(claims, "mfa") == true || used_multi_factor(claims) || claim(claims, "sso_connection_id").is_a?(String)
  end

  # The organization-level MFA requirement. With no argument: true when the active organization does not
  # require MFA or the user satisfied it (+org_mfa_ok+). With an organization id (or external id): the same, for
  # that organization, which must also be the one the token is for.
  def mfa_org_satisfied(claims, org_id_or_external_id = nil)
    required = claim(claims, "org_mfa_required") == true
    ok = claim(claims, "org_mfa_ok") == true
    return !required || ok if org_id_or_external_id.nil?

    matches = claim(claims, "org_id") == org_id_or_external_id || claim(claims, "org_external_id") == org_id_or_external_id
    return ok && (matches || claim(claims, "org_id").nil?) if required

    matches
  end

  def claim(claims, key)
    return nil unless claims.respond_to?(:key?)

    claims.key?(key) ? claims[key] : claims[key.to_sym]
  end
  private_class_method :claim

  class VerifyResult
    # See {Atlas.authenticated_within}.
    def authenticated_within?(max_age_seconds, now: nil) = ok? && Atlas.authenticated_within(claims, max_age_seconds, now: now)

    # See {Atlas.used_multi_factor}.
    def used_multi_factor? = ok? && Atlas.used_multi_factor(claims)

    # See {Atlas.mfa_satisfied}.
    def mfa_satisfied? = ok? && Atlas.mfa_satisfied(claims)
  end
end
