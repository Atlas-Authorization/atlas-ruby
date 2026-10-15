# Changelog

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
