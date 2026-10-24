# frozen_string_literal: true

require_relative "transport"

require_relative "resources/users"
require_relative "resources/sessions"
require_relative "resources/organizations"
require_relative "resources/roles"
require_relative "resources/oauth_clients"
require_relative "resources/resource_servers"
require_relative "resources/app_roles"
require_relative "resources/sso_connections"
require_relative "resources/custom_oauth_providers"
require_relative "resources/action_gallery"
require_relative "resources/scim_tokens"
require_relative "resources/domains"
require_relative "resources/waitlist"
require_relative "resources/restrictions"
require_relative "resources/attack_protection"
require_relative "resources/actor_tokens"
require_relative "resources/invitations"
require_relative "resources/webhooks"
require_relative "resources/sign_in_tokens"
require_relative "resources/audit_logs"
require_relative "resources/jwt_templates"
require_relative "resources/api_keys"
require_relative "resources/oauth_providers"
require_relative "resources/sso_onboarding"
require_relative "resources/scim_provisioning"
require_relative "resources/fga"
require_relative "resources/rate_limit"
require_relative "resources/risk_based_mfa"
require_relative "resources/bot_signals"
require_relative "resources/network_acls"
require_relative "resources/managed_waf"
require_relative "resources/log_streams"
require_relative "resources/logout_notify_endpoints"
require_relative "resources/branding"
require_relative "resources/email_templates"
require_relative "resources/sms_templates"
require_relative "resources/localizations"
require_relative "resources/actions"
require_relative "resources/billing"
require_relative "resources/policies"
require_relative "resources/messaging"
require_relative "resources/import_export"
require_relative "resources/data_subject_requests"
require_relative "resources/radius_clients"
require_relative "resources/lti_platforms"
require_relative "resources/instance"
require_relative "resources/instance_security"
require_relative "resources/referrals"
require_relative "resources/user_hooks"
require_relative "resources/tokens"
require_relative "resources/email_addresses"
require_relative "resources/organization_settings_schema"
require_relative "resources/design"
require_relative "resources/audit_events"
require_relative "resources/captcha"
require_relative "resources/config_changelog"
require_relative "resources/connectors"
require_relative "resources/directory"
require_relative "resources/diagnostics"
require_relative "resources/entitlement_overrides"
require_relative "resources/events"
require_relative "resources/legacy_auth_connection"
require_relative "resources/better_auth_imports"
require_relative "resources/better_auth_bridge"
require_relative "resources/machines"
require_relative "resources/mcp"
require_relative "resources/mcp_connector"
require_relative "resources/notifications"
require_relative "resources/openfga"
require_relative "resources/org_ldap_connections"
require_relative "resources/pca"
require_relative "resources/redirect_urls"
require_relative "resources/session_exchange_apps"
require_relative "resources/testing"
require_relative "resources/tickets"
require_relative "resources/usage"
require_relative "resources/platform"
require_relative "resources/credentials"
require_relative "resources/privacy"
require_relative "resources/integrations"
require_relative "resources/status"
require_relative "resources/notices"
require_relative "resources/misc_v2"

module Atlas
  # The typed management client for the Atlas Backend API — the secret-key
  # surface, the Ruby peer of TypeScript's +createAtlasClient+.
  #
  # Each namespace is one memoized accessor handing the shared, config-bound
  # transport to a resource class, so this file reads as a table of contents for
  # the whole surface.
  #
  #   atlas = Atlas::Client.new("sk_live_...")
  #   user  = atlas.users.create(email_address: "ada@example.com")
  #   Atlas.paginate(atlas.organizations).each { |org| puts org["name"] }
  class Client
    # @param secret_key [String] the instance secret key (+sk_...+). Sent as
    #   +Authorization: Bearer <key>+ on every request; never logged, never in a URL.
    # @param api_url [String] base URL of the instance's Backend API.
    # @param http [#call, nil] injectable requester (tests, custom transport).
    # @param open_timeout [Numeric] connect timeout, seconds.
    # @param read_timeout [Numeric] read timeout, seconds.
    # @param strict [Boolean, nil] strict request bodies. +true+ sends
    #   +Atlas-Strict: true+ on every write, so a body field the endpoint does
    #   not accept is refused with 422 +UNKNOWN_FIELD+ instead of being ignored.
    #   +false+ sends +Atlas-Strict: false+ (opting out of an instance-wide
    #   strict default). +nil+ (the default) sends nothing.
    # @param on_unknown_fields [#call, nil] called with an {Atlas::UnknownFields}
    #   (+fields+, +method+, +path+) whenever a successful write reports body
    #   fields the endpoint ignored (the +Atlas-Unknown-Fields+ response header).
    #   Handy for logging typos: +->(w) { logger.warn("ignored: #{w.fields}") }+.
    # @param traceparent [String, nil] a W3C +traceparent+ header value sent on every
    #   request, so Atlas stores it as the trace of everything the call emits
    #   (webhook deliveries, referral calls, verify errors). See {Atlas::Trace}.
    # @param secret_recipient [String, nil] an +x25519:<base64 public key>+ sent as
    #   +X-Secret-Recipient+ on every request: each shown-once secret in an answer comes back
    #   sealed to it (+sealed_secret+, +sealed_client_secret+, +sealed_webhook_secret+, with
    #   +secrets_sealed+ naming the fields) and the plaintext field is absent.
    def initialize(secret_key, api_url: DEFAULT_API_URL, http: nil,
                   open_timeout: 30, read_timeout: 30, strict: nil, on_unknown_fields: nil, traceparent: nil,
                   secret_recipient: nil)
      @transport = Transport.new(
        secret_key: secret_key, api_url: api_url, http: http,
        open_timeout: open_timeout, read_timeout: read_timeout,
        strict: strict, on_unknown_fields: on_unknown_fields, traceparent: traceparent,
        secret_recipient: secret_recipient
      )
    end

    # @return [Atlas::Transport] the underlying config-bound transport.
    attr_reader :transport

    # A client sharing this one's key and connection settings but with some
    # options replaced — the per-call override for strict bodies:
    #
    #   atlas.with_options(strict: false).users.update("user_1", { legacy_field: 1 })
    #
    # @return [Atlas::Client]
    def with_options(strict: Transport::INHERIT, on_unknown_fields: Transport::INHERIT, traceparent: Transport::INHERIT,
                     secret_recipient: Transport::INHERIT)
      copy = self.class.allocate
      copy.instance_variable_set(:@transport, @transport.with(strict: strict, on_unknown_fields: on_unknown_fields,
                                                              traceparent: traceparent,
                                                              secret_recipient: secret_recipient))
      copy
    end

    def users            = @users ||= Resources::Users.new(@transport)
    def sessions         = @sessions ||= Resources::Sessions.new(@transport)
    def organizations    = @organizations ||= Resources::Organizations.new(@transport)
    def roles            = @roles ||= Resources::Roles.new(@transport)
    def permissions      = @permissions ||= Resources::Permissions.new(@transport)
    def oauth_clients     = @oauth_clients ||= Resources::OAuthClients.new(@transport)
    def resource_servers  = @resource_servers ||= Resources::ResourceServers.new(@transport)
    def app_roles         = @app_roles ||= Resources::AppRoles.new(@transport)
    def oauth_initial_access_tokens = @oauth_initial_access_tokens ||= Resources::OAuthInitialAccessTokens.new(@transport)
    def sso_connections   = @sso_connections ||= Resources::SsoConnections.new(@transport)
    def scim_tokens       = @scim_tokens ||= Resources::ScimTokens.new(@transport)
    def domains           = @domains ||= Resources::Domains.new(@transport)
    def waitlist          = @waitlist ||= Resources::Waitlist.new(@transport)
    def allowlist         = @allowlist ||= Resources::Restriction.new(@transport, "/v1/allowlist_identifiers")
    def blocklist         = @blocklist ||= Resources::Restriction.new(@transport, "/v1/blocklist_identifiers")
    def attack_protection = @attack_protection ||= Resources::AttackProtection.new(@transport)
    def actor_tokens      = @actor_tokens ||= Resources::ActorTokens.new(@transport)
    def invitations       = @invitations ||= Resources::Invitations.new(@transport)
    def webhooks          = @webhooks ||= Resources::Webhooks.new(@transport)
    def sign_in_tokens    = @sign_in_tokens ||= Resources::SignInTokens.new(@transport)
    def audit_logs        = @audit_logs ||= Resources::AuditLogs.new(@transport)
    def jwt_templates     = @jwt_templates ||= Resources::JwtTemplates.new(@transport)
    def api_keys          = @api_keys ||= Resources::ApiKeys.new(@transport)
    def oauth_providers   = @oauth_providers ||= Resources::OAuthProviders.new(@transport)
    def custom_oauth_providers = @custom_oauth_providers ||= Resources::CustomOAuthProviders.new(@transport)
    def sso_onboarding    = @sso_onboarding ||= Resources::SsoOnboarding.new(@transport)
    def scim_provisioning = @scim_provisioning ||= Resources::ScimProvisioning.new(@transport)
    def fga               = @fga ||= Resources::Fga.new(@transport)
    def rate_limit_policy = @rate_limit_policy ||= Resources::RateLimitPolicy.new(@transport)
    def risk_based_mfa    = @risk_based_mfa ||= Resources::RiskBasedMfa.new(@transport)
    def bot_signals       = @bot_signals ||= Resources::BotSignals.new(@transport)
    def network_acls      = @network_acls ||= Resources::NetworkAcls.new(@transport)
    def managed_waf       = @managed_waf ||= Resources::ManagedWaf.new(@transport)
    def log_streams       = @log_streams ||= Resources::LogStreams.new(@transport)
    def logout_notify_endpoints = @logout_notify_endpoints ||= Resources::LogoutNotifyEndpoints.new(@transport)
    def branding          = @branding ||= Resources::Branding.new(@transport)
    def email_templates   = @email_templates ||= Resources::EmailTemplates.new(@transport)
    def sms_templates     = @sms_templates ||= Resources::SmsTemplates.new(@transport)
    def localizations     = @localizations ||= Resources::Localizations.new(@transport)
    def actions           = @actions ||= Resources::Actions.new(@transport)
    def action_gallery    = @action_gallery ||= Resources::ActionGallery.new(@transport)
    def action_templates  = @action_templates ||= Resources::ActionTemplates.new(@transport)
    def billing           = @billing ||= Resources::Billing.new(@transport)
    def policies          = @policies ||= Resources::Policies.new(@transport)
    def policy_source     = @policy_source ||= Resources::PolicySource.new(@transport)
    def messaging         = @messaging ||= Resources::Messaging.new(@transport)
    def import_export     = @import_export ||= Resources::ImportExport.new(@transport)
    def data_subject_requests = @data_subject_requests ||= Resources::DataSubjectRequests.new(@transport)
    def radius_clients    = @radius_clients ||= Resources::RadiusClients.new(@transport)
    def lti_platforms     = @lti_platforms ||= Resources::LtiPlatforms.new(@transport)
    def instance          = @instance ||= Resources::Instance.new(@transport)
    def instance_security = @instance_security ||= Resources::InstanceSecurity.new(@transport)
    def referrals         = @referrals ||= Resources::Referrals.new(@transport)
    def user_hooks        = @user_hooks ||= Resources::UserHooks.new(@transport)
    def tokens            = @tokens ||= Resources::Tokens.new(@transport)
    def email_addresses   = @email_addresses ||= Resources::EmailAddresses.new(@transport)
    def organization_settings_schema = @organization_settings_schema ||= Resources::OrganizationSettingsSchema.new(@transport)
    def design            = @design ||= Resources::Design.new(@transport)
    def audit_events      = @audit_events ||= Resources::AuditEvents.new(@transport)
    def captcha           = @captcha ||= Resources::Captcha.new(@transport)
    def config_changelog  = @config_changelog ||= Resources::ConfigChangelog.new(@transport)
    def connectors        = @connectors ||= Resources::Connectors.new(@transport)
    def directory         = @directory ||= Resources::Directory.new(@transport)
    def diagnostics       = @diagnostics ||= Resources::Diagnostics.new(@transport)
    def entitlement_overrides = @entitlement_overrides ||= Resources::EntitlementOverrides.new(@transport)
    def events            = @events ||= Resources::Events.new(@transport)
    def legacy_auth_connection = @legacy_auth_connection ||= Resources::LegacyAuthConnection.new(@transport)
    def better_auth_imports = @better_auth_imports ||= Resources::BetterAuthImports.new(@transport)
    def better_auth_bridge = @better_auth_bridge ||= Resources::BetterAuthBridge.new(@transport)
    def machines          = @machines ||= Resources::Machines.new(@transport)
    def mcp               = @mcp ||= Resources::Mcp.new(@transport)
    def mcp_connector     = @mcp_connector ||= Resources::McpConnector.new(@transport)
    def notifications     = @notifications ||= Resources::Notifications.new(@transport)
    def openfga           = @openfga ||= Resources::OpenFga.new(@transport)
    def org_ldap_connections = @org_ldap_connections ||= Resources::OrgLdapConnections.new(@transport)
    def pca               = @pca ||= Resources::Pca.new(@transport)
    def redirect_urls     = @redirect_urls ||= Resources::RedirectUrls.new(@transport)
    def session_exchange_apps = @session_exchange_apps ||= Resources::SessionExchangeApps.new(@transport)
    def testing           = @testing ||= Resources::Testing.new(@transport)
    def tickets           = @tickets ||= Resources::Tickets.new(@transport)
    def usage             = @usage ||= Resources::Usage.new(@transport)
    def whoami            = @whoami ||= Resources::Whoami.new(@transport)
    def secret_keys       = @secret_keys ||= Resources::SecretKeys.new(@transport)
    def keys              = @keys ||= Resources::Keys.new(@transport)
    def partner_links     = @partner_links ||= Resources::PartnerLinks.new(@transport)
    def atlas_id_apps     = @atlas_id_apps ||= Resources::AtlasIdGrants.new(@transport)
    def privacy           = @privacy ||= Resources::Privacy.new(@transport)
    def integrations      = @integrations ||= Resources::Integrations.new(@transport)
    def status            = @status ||= Resources::Status.new(@transport)
    def notices           = @notices ||= Resources::Notices.new(@transport)
    def security_advisories = @security_advisories ||= Resources::SecurityAdvisories.new(@transport)
    def audit_exports     = @audit_exports ||= Resources::AuditExports.new(@transport)
    def sub_processors    = @sub_processors ||= Resources::SubProcessors.new(@transport)
    def entitlements      = @entitlements ||= Resources::Entitlements.new(@transport)
    def integration_health = @integration_health ||= Resources::IntegrationHealth.new(@transport)
    def embed             = @embed ||= Resources::Embed.new(@transport)
    def openapi           = @openapi ||= Resources::OpenApi.new(@transport)
    def delivery_health   = @delivery_health ||= Resources::DeliveryHealth.new(@transport)
    def meta              = @meta ||= Resources::Meta.new(@transport)
    # Platform-key surface: construct the client with a +psk_+ key to use it.
    def platform          = @platform ||= Resources::Platform.new(@transport)
  end
end
