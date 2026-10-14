# Changelog

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
