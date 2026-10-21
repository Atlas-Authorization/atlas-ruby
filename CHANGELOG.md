# Changelog

## 0.9.0

- **Referral attribution settings.** New `referrals` namespace: `get`, `update(body, idempotency_key: nil)` (`GET`/`PATCH /v1/instance/referrals`; `nil` clears; nested `security` with `challenge_referred_signups`, `on_high_risk`, `hold_until_email_verified`, `max_referred_signups_per_ip_hour`; `signing_secret` and `api_key` are write-only), `test` (`ok`, `http_status`, `latency_ms`, `error`), `list_calls(params = {})` (`limit`, `status`, `kind`, `user_id`) and `retry_call(id, idempotency_key: nil)`.
- **Users.** User objects carry `referral` (`partner_id`, `referrer_external_id`, `referrer_user_id`, `matched_via`, `status`, `risk_level`, `flagged`, or `nil`), `referral_code` and `referral_link`. `users.create` accepts `referral` (`code`, `click_id`, `anon_id`) and `referral_code`; `users.update` accepts `referral_code` (`nil` clears). New `users.flag_referral(id, reason: nil, idempotency_key: nil)`.
- **Webhooks.** New event `user.referral_attributed` (the referral platform answered after `user.created`).
- **Error codes.** `Atlas::ErrorCode` adds `REFERRALS_NOT_CONFIGURED` (422) and `REFERRAL_CODE_TAKEN` (409). Preflight can report `referrals_enabled_unverified` and `referrals_without_bot_protection`.
- Compatible: new methods only.

## 0.8.0

- **Trusted reverse proxy secret.** `instance_security.get_proxy_secret`, `create_proxy_secret(body = OMIT)` (`{ overlap_seconds: }` on a rotation: default 86400, `0` stops the old secret now, at most 604800; the response carries `secret`, shown once, and `rotated`) and `delete_proxy_secret`. The view carries `set`, `created_at`, `previous_expires_at`, `secret_header` and `client_ip_header`.
- **Webhook secret rotation with an overlap.** `webhooks.endpoints.rotate_secret(id, body = OMIT)` takes `{ overlap_seconds: }` (default 0, at most 604800). The response carries `overlap_seconds` and `previous_secret_expires_at`; endpoint objects carry `previous_secret_expires_at` while an overlap is open.
- **Per-instance platform rotation with an overlap.** `platform.apps.rotate_instance_secret(id, instance_id, body = OMIT, idempotency_key: nil)` takes `{ overlap_seconds: }` (default 259200, `0` revokes the prior keys now). The response carries `app_id`, `instance_id`, `overlap_seconds` and `previous_keys_expire_at`. Without a body the server now keeps the prior keys for 72 hours; pass `{ overlap_seconds: 0 }` for the old behaviour.
- **Sign in with Atlas apps.** `platform.atlas_id_apps.rotate_secret(id, body = OMIT)` (default 24 hours) and `rotate_webhook_secret(id, body = OMIT)` (default 0) take `{ overlap_seconds: }`. App objects carry `previous_secret_expires_at`, `secret_issued_at` and `webhook_previous_secret_expires_at`.
- Compatible: every existing call keeps its signature.

## 0.7.0

- **OAuth client secret rotation with overlap.** `oauth_clients.rotate_secret(id, body = OMIT, idempotency_key: nil)` takes `{ overlap_seconds: }` (default 86400, `0` revokes the old secret now, at most 604800). The response carries `client_secret`, `overlap_seconds` and `previous_secret_expires_at`; client objects carry `previous_secret_expires_at`.
- **Development email sender.** `messaging.get_development_email`, `enable_development_email(body)` (`provider_id`, or `transport` + `config`) and `disable_development_email`.
- **Managed email on your own provider account.** `messaging.create_managed_email` takes `transport` (`resend` | `brevo`) with `config: { api_key: }`, or `provider_id`. Responses carry `backend`, `provider_id` and `feedback_webhook`; `limits` is now `nil` and `reputation` is `your_provider_account`.
- **Provider mode.** `messaging.set_email` accepts `mode` (`standard` | `development`); providers carry `id` and `mode`.
- **Allowed origins with an integration.** `instance.update` and the platform app, instance and accountless-app bodies accept `allowed_origins` entries `{ origin:, integration: }` (`redirect` | `embedded` | `auto` | `nil`). Instance and platform app objects carry `allowed_origin_integrations`, `issuer`, `discovery_url` and `jwks_uri` (and `frontend_api_host` on platform apps).
- Responses also carry `integration` and `checks[].applies` on login readiness, `verification` (`status`, `strategy`) on email addresses, and `audiences` on branding.
- **Error codes.** `Atlas::ErrorCode` adds `READ_ONLY_FIELD`, `DEVELOPMENT_EMAIL_NOT_ALLOWED`, `DEVELOPMENT_EMAIL_UNAVAILABLE`, `DEVELOPMENT_EMAIL_LIMIT_REACHED` and `DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED`.
- **Webhooks, several signatures.** `Atlas::Webhook.verify` accepts an `atlas-signature` header with several space-separated `v1,<signature>` entries and verifies when any one matches (each compared in constant time). A single signature works as before.

## 0.6.0

- **Back-channel logout, retryable failures.** `Atlas::InvalidLogoutTokenError#retryable?` is true for `:no_keys`: the issuer's keys could not be fetched (a network error, a JWKS outage, or a just-rotated key whose refetch failed). Answer `503` with `Retry-After` then, so Atlas retries the delivery, and `400` otherwise. A token whose `kid` is unknown after a failed JWKS refetch is now `:no_keys` (was `:invalid_signature`).
- **Webhook verification.** `Atlas::Webhook.verify(body:, headers:, secret:, now_ms: nil)` returns a
  `Result` (`verified?`, `reason`, `event`, `delivery_id`, `timestamp`). `delivery_id` is the signed
  `atlas-id` header, the same on every retry of one event: deduplicate on it. Accepts plain or Rack-style
  (`HTTP_ATLAS_ID`) headers.
- **Domain moves.** `instance.move_origin(from:, to:, dry_run:)` (a Hash body) rewrites every URL on one origin to another; `platform.atlas_id_apps.move_origin(id, body)` does it for one app.
- **Connections and integrations.** `instance.connections`, and `instance.get_ / set_ / delete_chatly_integration` and `..._forumulate_integration`.
- **Logout fan-out.** New `logout_notify_endpoints` namespace: `list`, `create`, `get`, `update`, `delete`, `list_deliveries`.
- **Managed email.** `messaging.get_managed_email`, `create_managed_email`, `verify_managed_email`, `delete_managed_email(force:)`.
- **Back-channel logout logs.** `oauth_clients.list_backchannel_deliveries` / `test_backchannel_logout` and the same on `platform.atlas_id_apps`.
- **Sign in with Atlas apps.** `platform.atlas_id_apps.preflight`, `find_users(id, email)`, `revoke_grant(id, grant_id)`, `rotate_webhook_secret(id)`; app responses carry `webhook_url`, `webhook_events`, `webhook_active` (and `webhook_secret` once).
- **Publisher.** `platform.atlas_id_publisher.get / set / update(skip_consent:) / delete / verify`, and `platform.config_changelog(params)`.
- Responses now also carry `version` on users, `culture` and `declared_cookies` on cookie consent, `sdk_versions_seen` on preflight, `error` and `location` on webhook deliveries, and `event_catalog` on the webhook endpoint list.

## 0.5.1

- **Captcha is bring-your-own-keys.** `Atlas::ErrorCode::CAPTCHA_KEYS_REQUIRED` (422) and `CAPTCHA_IN_USE` (409, `meta["flows"]`).
- `instance_security.set_captcha_secret` documents `provider:` so the secret can be stored before captcha is turned on.
- `instance_security.delete_captcha_secret(provider:, force:)` — `force: true` removes a secret a flow uses and turns those flows off (`flows_turned_off`).

## 0.5.0

All changes are backward compatible: every new field and parameter is optional.

### Added

- OAuth clients: `skip_logout_confirmation` (boolean) documented on `oauth_clients.create` and `oauth_clients.update`; client objects carry it (default `false`). First-party clients only (422 `VALIDATION_FAILED`, param `skip_logout_confirmation`, on a third-party client). When true, RP-initiated logout with this client and an exactly registered `post_logout_redirect_uri` ends the session and redirects straight back with `state`, without the confirmation page.
- Cookie consent: `instance.set_cookie_consent` accepts `settings_link` (`{ label, preset, attributes }`, or `nil` for no link). `label` is required (1-60 chars); `preset` is one of `"cookiemunch"`, `"cookiebot"`, `"onetrust"`, `"custom"` or `nil`; `attributes` is a Hash of String => String (`data-*`, `aria-*`, `id`, `class`, `href`; at most 10, values up to 200 chars). The cookie-consent setting returned by `get_cookie_consent`, `set_cookie_consent` and `delete_cookie_consent` carries `settings_link` (`nil`, or `{ label, preset, attributes, rendered_attributes }`).
- `Atlas::Resources::Instance::COOKIE_CONSENT_PRESETS` — the known settings-link presets (a response's `preset` stays a String, so new values still read fine).
- `messaging.delete_channel(channel, force: false)` — `force: true` sends `?force=true` and removes the email provider even while email-dependent features are on.
- `Atlas::ErrorCode::EMAIL_PROVIDER_IN_USE` — removing the email provider is refused with a 409 while email-dependent features are on and nothing else would deliver email; the error's `meta["features"]` lists them (e.g. `emailCode`, `emailLink`, `emailVerification`, `passwordReset`).
- Sessions: `idle_expires_at` (epoch ms, same value as `abandon_at`) documented on every session object, including `users.list_sessions` items, which also carry `last_active_organization_id` and `impersonated_by` (String or `nil`).

## 0.4.0

### Added

- `sessions.touch(id)` — `POST /v1/sessions/{id}/touch`, backend session keep-alive. Returns the session plus `extended` (boolean). Session objects now carry `idle_expires_at` (epoch ms).
- API key spend caps: `api_keys.create` and `api_keys.update` document `limits` (array of `{ unit, amount, period: "request" | "day" | "month" | "total" }`, or `nil` to clear). API key objects carry `limits` and `usage` (`[{ unit, period, amount, used, remaining, window_start, resets_at }]`).
- `api_keys.record_usage(id, amount:, unit:, idempotency_key: nil)` — `POST /v1/api_keys/{id}/usage`, returns an `api_key_usage_debit` (`key_id`, `unit`, `amount`, `allowed`, `code`, `exceeded`, `usage`, `counters`, `idempotent_replay`).
- `api_keys.get_usage(id)` — `GET /v1/api_keys/{id}/usage`, returns an `api_key_usage` (`key_id`, `limits`, `usage`, `counters`).
- `api_keys.verify` valid results carry `name`, `scopes`, `constraints`, `limits` and `usage`.
- `notify` (boolean) documented on `users.create` and `import_export.import_users`.
- Webhook events `api_key.created`, `api_key.updated` and `api_key.limit_reached`; the `api_key` payload carries `name`, `claims`, `scopes`, `constraints`, `limits`, `max_token_lifetime_seconds`, `expires_at`, `created_at` and `updated_at`.
- `Atlas::ErrorCode::LIMIT_EXCEEDED`, `SESSION_REVOKED`, `SESSION_IDLE_EXPIRED`, `SESSION_EXPIRED`.

## 0.3.0

### Added

- Full Backend API and platform API coverage: every operation in the public API reference now has a method.
- `platform` namespace (platform key): `apps` (provision, archive, transfer, claim, rotate secrets, instances), `atlas_id_apps` (Sign in with Atlas apps, incl. post-logout redirect URIs, back- and front-channel logout URIs, branding with copy and design, secret rotation, design preview) and `design_assets` (image uploads).
- `design` namespace: read, replace, patch and preview the sign-in page design, upload/list/delete design images, and the design catalog. Organization designs via `organizations.get_design` / `replace_design` / `update_design`.
- Raw-bytes uploads: `design.upload_asset` and `platform.design_assets.upload` send image bytes with their content type (detected from the bytes when not given).
- `instance.preflight` (setup findings with severity, code, message, fix and subject) and cookie-consent settings (`get_cookie_consent`, `set_cookie_consent`, `delete_cookie_consent`).
- Strict request bodies: `Atlas::Client.new(key, strict: true)` sends `Atlas-Strict: true` on every write; `with_options(strict: false)` overrides it per call; `on_unknown_fields:` reports fields a write sent that the endpoint ignored.
- `Atlas::BackchannelLogout` verifies OpenID Connect back-channel logout tokens, with optional replay protection (`Atlas::MemoryJtiStore` or your own store).
- `Atlas::ErrorCode` constants (`UNKNOWN_FIELD`, `EMAIL_DELIVERY_NOT_CONFIGURED`, `EMAIL_PROVIDER_REQUIRED`, `PLAN_IN_USE`, `WRONG_KEY_SURFACE`, `INVALID_KEY`, ...).
- `oauth_providers.list` accepts `provider:` and `configured:` filters; `upsert` documents `display_name`, `icon_url`, `mode` and wallet `settings` (nil clears a setting).
- Webhook endpoints: `update`, `reveal_secret`, `rotate_secret`, `test`; `webhooks.redeliver`; `webhooks.deliveries` accepts `limit:`.
- `entitlement_overrides`, documented organization policy fields (`Organizations::ORG_POLICY_FIELDS`), and per-transport messaging config tables (`Messaging::EMAIL_TRANSPORTS`, `Messaging::SMS_TRANSPORTS`).
- New namespaces: `audit_events`, `captcha`, `config_changelog`, `connectors`, `directory`, `diagnostics`, `email_addresses`, `events`, `legacy_auth_connection`, `machines`, `mcp`, `mcp_connector`, `notifications`, `openfga`, `org_ldap_connections`, `organization_settings_schema`, `pca`, `redirect_urls`, `session_exchange_apps`, `testing`, `tickets`, `usage`; and many new methods on `users`, `organizations`, `billing`, `data_subject_requests`, `invitations`, `waitlist`, `sessions`, `sign_in_tokens`, `api_keys` and `oauth_clients`.

### Changed

- A custom `http:` requester may now return a third element, a Hash of response headers. Two-element returns keep working.

## 0.2.0

- Rails integration. Earlier releases: see the repository history.
