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
end
