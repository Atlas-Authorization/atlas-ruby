# frozen_string_literal: true

require "uri"

module Atlas
  # Atlas-specific claims on the ID tokens and userinfo of an OIDC relying party: the
  # organization a sign-in was made in (+org_id+, +org_slug+, +org_role+,
  # +org_permissions+), every membership (+orgs+, with the +organizations+ scope) and the
  # enterprise SSO connection (+sso_connection_id+, +sso_organization_id+,
  # +sso_connection_type+, +sso_tenant_id+, +sso_issuer+, +sso_domain+). Pass the verified claims of the token (a Hash).
  #
  #   org = Atlas::OIDC.organization_of(claims)  # => { id:, slug:, role:, permissions: } or nil
  #   Atlas::OIDC.organizations_of(claims)       # => [{ id:, slug:, role: }, ...] or nil
  #   Atlas::OIDC.sso_of(claims)                 # => { connection_id:, organization_id:, type:, tenant_id:, issuer:, domain: } or nil
  #   url = Atlas::OIDC.authorize_url_with_organization(authorize_url, "acme")
  module OIDC
    # The scope that adds the +orgs+ membership list to the ID token and userinfo.
    SCOPE_ORGANIZATIONS = "organizations"
    # The authorize parameter that pins the organization (id or slug) a sign-in is made in.
    ORGANIZATION_PARAM = "organization"

    module_function

    def organization_of(claims)
      id = fetch(claims, "org_id")
      return nil unless id.is_a?(String)

      perms = fetch(claims, "org_permissions")
      slug = fetch(claims, "org_slug")
      role = fetch(claims, "org_role")
      {
        id: id,
        slug: slug.is_a?(String) ? slug : "",
        role: role.is_a?(String) ? role : "",
        permissions: perms.is_a?(Array) ? perms.grep(String) : []
      }
    end

    def organizations_of(claims)
      orgs = fetch(claims, "orgs")
      return nil unless orgs.is_a?(Array)

      orgs.filter_map do |o|
        next unless o.is_a?(Hash)

        id = fetch(o, "id")
        next unless id.is_a?(String)

        slug = fetch(o, "slug")
        role = fetch(o, "role")
        { id: id, slug: slug.is_a?(String) ? slug : "", role: role.is_a?(String) ? role : "" }
      end
    end

    # The enterprise SSO context of a sign-in (works on ID-token, userinfo and session claims).
    # +organization_id+ is the Atlas organization that owns the connection (nil for an
    # instance-wide one), independent of +org_id+: scope a per-organization "require SSO" rule
    # on it, never on "signed in via SSO". +type+ is "saml" or "oidc" (nil when absent).
    def sso_of(claims)
      id = fetch(claims, "sso_connection_id")
      return nil unless id.is_a?(String)

      str = ->(k) { v = fetch(claims, k); v.is_a?(String) ? v : nil }
      type = str.call("sso_connection_type")
      { connection_id: id, organization_id: str.call("sso_organization_id"),
        type: %w[saml oidc].include?(type) ? type : nil, tenant_id: str.call("sso_tenant_id"),
        issuer: str.call("sso_issuer"), domain: str.call("sso_domain") }
    end

    # Add (or replace) the +organization+ authorize parameter: the sign-in must be made in
    # that organization (a user who is not a member gets +access_denied+) and the token's
    # +org_*+ claims are that organization's.
    def authorize_url_with_organization(authorize_url, organization)
      uri = URI.parse(authorize_url)
      pairs = URI.decode_www_form(uri.query.to_s).reject { |k, _| k == ORGANIZATION_PARAM }
      pairs << [ORGANIZATION_PARAM, organization]
      uri.query = URI.encode_www_form(pairs)
      uri.to_s
    end

    def fetch(hash, key)
      return nil unless hash.respond_to?(:key?)

      hash.key?(key) ? hash[key] : hash[key.to_sym]
    end
    private_class_method :fetch
  end
end
