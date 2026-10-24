# frozen_string_literal: true

module Atlas
  # Captcha providers (+auth_config.captcha.provider+). Captcha is
  # bring-your-own-keys: store the secret first. +vercel_botid+ is secret-only:
  # set +attestationUrl+ instead of a site key.
  CAPTCHA_PROVIDERS = %w[
    none atlas hcaptcha turnstile recaptcha recaptcha_v3 recaptcha_enterprise funcaptcha friendly yandex
    geetest mcaptcha capy seon awswaf perimeterx akamai kasada incapsula captchafox vercel_botid
  ].freeze

  # +auth_config.accountLinkingTrust+ values.
  LINKING_TRUST_LEVELS = %w[always verified never].freeze

  # Billing providers an instance can sell end-user plans through (bring your own key).
  BILLING_PROVIDERS = %w[stripe polar dodo creem chargebee autumn commet].freeze

  # Where the token-signing key can live.
  SIGNING_KEY_PROVIDERS = %w[local aws_kms gcp_kms azure_key_vault].freeze

  # A session's custom data changed.
  WEBHOOK_EVENT_SESSION_UPDATED = "session.updated"
  # A dormant account signed in again.
  WEBHOOK_EVENT_USER_REACTIVATED = "user.reactivated"
  # A user accepted a policy version (payload: +policy_acceptance+ with its evidence).
  WEBHOOK_EVENT_USER_POLICY_ACCEPTED = "user.policy_accepted"
  # A policy version was published.
  WEBHOOK_EVENT_POLICY_VERSION_PUBLISHED = "policy.version_published"
  # The security notice sent when a dormant account signs in again.
  EMAIL_TEMPLATE_ACCOUNT_REACTIVATED = "account_reactivated"

  # Webhook event names added with the integrator platform. Endpoints with
  # +event_naming+ +canonical+ / +both+ receive the canonical names; the aliases
  # stay valid for +legacy+ / +both+.
  WEBHOOK_EVENT_PRIVACY_REQUEST_UPDATED = "privacy_request.updated"
  WEBHOOK_EVENT_PRIVACY_REQUEST_COMPLETED = "privacy_request.completed"
  WEBHOOK_EVENT_USER_DELETION_SCHEDULED = "user.deletion_scheduled"
  WEBHOOK_EVENT_USER_DELETION_CANCELED = "user.deletion_canceled"
  WEBHOOK_EVENT_SECRET_KEY_EXPIRING = "secret_key.expiring"
  WEBHOOK_EVENT_SECRET_KEY_REVOKED = "secret_key.revoked"
  WEBHOOK_EVENT_ENDPOINT_FAILING = "webhook_endpoint.failing"
  WEBHOOK_EVENT_ENDPOINT_DISABLED = "webhook_endpoint.disabled"
  WEBHOOK_EVENT_ENDPOINT_RECOVERED = "webhook_endpoint.recovered"
  WEBHOOK_EVENT_DELIVERY_TARGET_FAILING = "delivery_target.failing"
  WEBHOOK_EVENT_DELIVERY_TARGET_DISABLED = "delivery_target.disabled"
  WEBHOOK_EVENT_DELIVERY_TARGET_RECOVERED = "delivery_target.recovered"
  WEBHOOK_EVENT_TEST = "webhook.test"
  WEBHOOK_EVENT_STATUS_INCIDENT_CREATED = "status.incident.created"
  WEBHOOK_EVENT_STATUS_INCIDENT_UPDATED = "status.incident.updated"
  WEBHOOK_EVENT_STATUS_INCIDENT_RESOLVED = "status.incident.resolved"

  # +since+ value for webhook replay / redelivery: from the start of the endpoint's last
  # failure streak.
  WEBHOOK_REPLAY_SINCE_FAILING = "failing_since"

  # OIDC relying parties: the scope that adds the +orgs+ membership list to the ID token.
  OIDC_SCOPE_ORGANIZATIONS = "organizations"

  # +event_naming+ values on a webhook endpoint.
  WEBHOOK_EVENT_NAMING = %w[canonical legacy both].freeze
  # +signature_versions+ values on a webhook endpoint.
  WEBHOOK_SIGNATURE_VERSIONS = %w[v1 v2].freeze

  # Scope names added with the integrator platform.
  SCOPE_PRIVACY_EXECUTE = "privacy:execute"
  SCOPE_PRIVACY_GRANTS_REVOKE = "privacy:grants:revoke"
  SCOPE_WEBHOOKS_REVEAL = "webhooks:reveal"

  # Referral provider ids. +referally+ is the old id of +referalli+; both are accepted.
  REFERRAL_PROVIDER_REFERALLI = "referalli"
  REFERRAL_PROVIDER_ALIASES = { "referally" => "referalli" }.freeze

  # Preflight finding codes added with the integrator platform.
  PREFLIGHT_CODES = %w[
    oauth_client_no_backchannel_logout_uri pkce_not_required passkey_without_uv auto_link_unverified
    integration_enabled_never_minted integration_verify_errors integration_receiver_failing cookie_consent_not_enabled
    status_dependency_unreachable status_dependency_outage
  ].freeze
end
