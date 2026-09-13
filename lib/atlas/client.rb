# frozen_string_literal: true

require_relative "transport"

require_relative "resources/users"
require_relative "resources/sessions"
require_relative "resources/organizations"
require_relative "resources/roles"
require_relative "resources/oauth_clients"
require_relative "resources/resource_servers"
require_relative "resources/sso_connections"
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
require_relative "resources/branding"
require_relative "resources/email_templates"
require_relative "resources/sms_templates"
require_relative "resources/localizations"
require_relative "resources/actions"
require_relative "resources/billing"
require_relative "resources/messaging"
require_relative "resources/import_export"
require_relative "resources/data_subject_requests"
require_relative "resources/radius_clients"
require_relative "resources/lti_platforms"
require_relative "resources/instance"
require_relative "resources/instance_security"
require_relative "resources/tokens"

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
    def initialize(secret_key, api_url: DEFAULT_API_URL, http: nil,
                   open_timeout: 30, read_timeout: 30)
      @transport = Transport.new(
        secret_key: secret_key, api_url: api_url, http: http,
        open_timeout: open_timeout, read_timeout: read_timeout
      )
    end

    # @return [Atlas::Transport] the underlying config-bound transport.
    attr_reader :transport

    def users            = @users ||= Resources::Users.new(@transport)
    def sessions         = @sessions ||= Resources::Sessions.new(@transport)
    def organizations    = @organizations ||= Resources::Organizations.new(@transport)
    def roles            = @roles ||= Resources::Roles.new(@transport)
    def permissions      = @permissions ||= Resources::Permissions.new(@transport)
    def oauth_clients     = @oauth_clients ||= Resources::OAuthClients.new(@transport)
    def resource_servers  = @resource_servers ||= Resources::ResourceServers.new(@transport)
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
    def sso_onboarding    = @sso_onboarding ||= Resources::SsoOnboarding.new(@transport)
    def scim_provisioning = @scim_provisioning ||= Resources::ScimProvisioning.new(@transport)
    def fga               = @fga ||= Resources::Fga.new(@transport)
    def rate_limit_policy = @rate_limit_policy ||= Resources::RateLimitPolicy.new(@transport)
    def risk_based_mfa    = @risk_based_mfa ||= Resources::RiskBasedMfa.new(@transport)
    def bot_signals       = @bot_signals ||= Resources::BotSignals.new(@transport)
    def network_acls      = @network_acls ||= Resources::NetworkAcls.new(@transport)
    def managed_waf       = @managed_waf ||= Resources::ManagedWaf.new(@transport)
    def log_streams       = @log_streams ||= Resources::LogStreams.new(@transport)
    def branding          = @branding ||= Resources::Branding.new(@transport)
    def email_templates   = @email_templates ||= Resources::EmailTemplates.new(@transport)
    def sms_templates     = @sms_templates ||= Resources::SmsTemplates.new(@transport)
    def localizations     = @localizations ||= Resources::Localizations.new(@transport)
    def actions           = @actions ||= Resources::Actions.new(@transport)
    def billing           = @billing ||= Resources::Billing.new(@transport)
    def messaging         = @messaging ||= Resources::Messaging.new(@transport)
    def import_export     = @import_export ||= Resources::ImportExport.new(@transport)
    def data_subject_requests = @data_subject_requests ||= Resources::DataSubjectRequests.new(@transport)
    def radius_clients    = @radius_clients ||= Resources::RadiusClients.new(@transport)
    def lti_platforms     = @lti_platforms ||= Resources::LtiPlatforms.new(@transport)
    def instance          = @instance ||= Resources::Instance.new(@transport)
    def instance_security = @instance_security ||= Resources::InstanceSecurity.new(@transport)
    def tokens            = @tokens ||= Resources::Tokens.new(@transport)
  end
end
