# Changelog

## 0.21.0 — 2026-10-30

### Added

- **Application webhooks.** `app_events` (`publish`, `list`, `get`), `app_events.types` (the event catalog: `list`, `create`, `get`, `update`, `delete`, by `aet_` id or type name) and `app_events.endpoints` (one organization's endpoints: `list`, `create`, `get`, `update`, `delete`, `rotate_secret`, `reveal_secret`, `test`, `deliveries`, `redeliver`, `replay`, `app_event_types`).
- **Standard Webhooks verifier.** `Atlas::Webhook.verify_standard(body:, headers:, secret:, now:, tolerance_sec:)` for application webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`, `whsec_` base64 key). Returns the same `Result` as `verify`.
- **Browser tickets.** `sessions.create_browser_ticket(user_id, redirect_url:, expires_in_seconds:)` (`POST /v1/sessions` with `mode: "browser_ticket"`); `sessions.create` accepts `mode`, `redirect_url`, `expires_in_seconds` too.
- **Sign-in URL for tests.** `testing.create_sign_in_url(user_id, redirect_url, expires_in_seconds:)` (`POST /v1/testing/sign_in_url`, development instances only).
- **Sign in with Atlas and hosted pages.** `instance.sign_in_with_atlas` and `instance.hosted_pages` (`get`, `update`).
- **Privacy integration.** `privacy.integration` (`get`, `connect`): consent manager, orchestrator, completion webhook and executor key in one idempotent call.
- Documented: `instance.update` result `warnings`; `api_keys` limit periods `second` and `minute`, `scopes`, `import` and `effective_scopes`.

### Deprecated

- `sign_in_tokens.create` and `revoke` (sunset 2027-04-01): use `sessions.create_browser_ticket`.

### Added (full Backend API coverage)

- **Full Backend API coverage.** 452 more operations, each with an exact-route test row. New namespaces on the client: `app_catalog`, `ldap_server_clients`, `journeys`, `groups` (with `rules`), `migrations` (with `imports`), `managed_grants`, `least_privilege`, `flags`, `mfa_factors` (with `yubikeys`, `smart_card_mappings`), `analytics` (with `reports`, `alert_rules`), `marketing`, `audit_event_schemas`, `directory_pull_sources`, `relay_agents`, `oauth_client_profiles`, `passkey_api`, `vc`, `listen`, `agent_registration`, `agents`, `agent_access_requests`, `workflows`, `page_templates`, `service_connectors`, `desktop_mfa`, `identity_verification`, `iga`, `scim_provisioning_presets`, `vault`, `connections`, `ssf`, `network_zones`, `access_policies`, `abac`, `resources` (the class is `Atlas::Resources::ProtectedResources`), `org_role_grants`, `devices`, `authz_decisions`, `policy_bundles`, `proxy_apps`, `mcp_gateways`.
- **Added to existing namespaces.** `users` (required actions, notes, guardians, saved searches and views, history, minor status, links, device keys), `organizations` (webhook endpoints, connected apps, connection secret), `oauth_clients` (app settings, workload identity, trusted issuers, exchange policy, profile, delegated UI, login and consent requests), `org_ldap_connections` (sync, sync runs, relay), `fga` and `openfga` (`list_users`, `read_changes`), `attack_protection` and `risk_based_mfa` (secrets), `actions.calls`, `instance.integrations.rotate_events_secret`, `integrations.run_card_action`, `delivery_health.get_scope`.
- `listen.stream_session` and `policy_bundles.archive` return the raw body as a String (the event stream is read to its end, not streamed).
- **Risk-event timeline.** `risk_based_mfa.list_events` (`GET /v1/risk_events`; query `user_id`, `level`, `limit`, `before`), `event_metrics` (`GET /v1/risk_events/metrics`) and `event_feedback(id, verdict)` (`POST /v1/risk_events/{id}/feedback`, verdict `legit` or `fraud`).
- **Fraud lookup.** `risk_based_mfa.fraud_lookup` (`POST /v1/fraud/lookup`).

## 0.20.0 — 2026-10-25

### Added

- **Test and review accounts for Sign in with Atlas apps.** `platform.atlas_id_apps.provisioned_accounts` (`list`, `create`, `get`, `remove`, `rotate_password`). A password comes back once, on `create` and `rotate_password`, as `password`, or as `sealed_password` when you pass `secret_recipient:`. Needs the `platform:atlas_id_apps:provision` scope, or `atlas_id_apps:<app id>:provision` for one app.
- **Verified domains.** `platform.domains` (`list`, `claim`, `check`, with `verify` as an alias, `remove`).
- **App settings.** `test_mode` and `provisioned_verified_domains_only` on Sign in with Atlas apps (create, update and the app object).
- `Atlas::ErrorCode::TEST_ACCOUNT_RESTRICTED` (403), `PROVISIONED_ACCOUNT_LIMIT_REACHED` (409) and `DOMAIN_NOT_VERIFIED` (422).

## 0.19.0 — 2026-10-25

### Added

- **Partner platforms.** `partner_platforms` (`list`, `get`, `set`, `delete`, `registration`, `store_token(partner, token, rotate:, api_base_url:)`, `deliveries(limit:)`). The partner token is write-only: no response carries it, only `token_set` and `token_prefix`.
- **Per-call audience.** `sessions.get_token` and `integrations.get_token` take `audience:`, `cbid:` and `audience_params:` (the integration's own parameter), sent as query parameters. The integration's `per_call_audience` (`param`, `template`, `allowed`, `any_matching`; `nil` turns it off) decides what is permitted.
- **Privacy orchestrator.** `site_id`, `partner_link_id` and `cancel_deletion_on_sign_in` on `privacy.orchestrator.set`; presets may carry `case_format`. Outbound partner links report `source: "registration"`.
- **Operator.** `keys.operator` documents `audiences` and `access_token_claims`.
- `users.list(include_deleted: true)` and `users.get(id, include_deleted: true)` return soft-deleted users, which the list leaves out by default.
- `Atlas::ErrorCode::MANAGED_WAF_NOT_CONFIGURED` (422, `meta.action`).
- The Sign in with Atlas grant routes (`platform.atlas_id_apps.find_users`, `revoke_grant`) also accept the secret key of the instance that manages the app; `atlas_id_apps.lookup` and `revoke_grant` are the same on the instance client.

## 0.18.0 — 2026-10-24

### Added

- **Enterprise SSO claims.** `Atlas::OIDC.sso_of` also returns `organization_id` (`sso_organization_id`, nil for an instance-wide connection) and `type` (`sso_connection_type`, `saml` or `oidc`); it works on ID-token, userinfo and session claims. Scope a per-organization "require SSO" rule on `organization_id`, never on "signed in via SSO".
- **Adopting a Sign in with Atlas app.** `platform.atlas_id_apps.set_managed_by(id, instance_id_or_nil)` (`PUT /v1/platform/atlas_id_apps/{id}/managed_by`). App objects carry `managed_via` (`instance_toggle` | `adopted`) and `button_rendered_origins`.
- **Instance-surface app setup check.** `atlas_id_apps.preflight(app_id)` (`GET /v1/atlas_id_apps/{id}/preflight`); both preflights answer `button_rendered_origins`, `authorize_requests_7d`, `fallback_origins`, `homepage_includes_script`.
- **Dry run.** `Atlas::DryRunResult.from(answer)` reads `mode` (`native` | `rollback` | `plan`), `validated`, `warnings`, `would_return`, `would_return_status`, `suppressed` and `validation_skipped`.
- **Sealed secrets.** `secret_recipient:` on `Atlas::Client.new` and `with_options` sends `X-Secret-Recipient` on every request, so every route that returns a shown-once secret answers with `sealed_secret` / `sealed_client_secret` / `sealed_webhook_secret` and `secrets_sealed`.

## 0.17.0 — 2026-10-24

### Added

- **Credentials.** `whoami.get`, `secret_keys` (`create` with `key_format` / `secret_recipient` / `dry_run:`, `list` with a `metadata:` filter, `get`, `update`, `rotate`, `revoke`), `keys.list`, `keys.revoke_leaked`, `keys.operator`, `keys.exchange_token` / `client_credentials` / `token_exchange` (`POST /v1/oauth/token`, form-encoded), `partner_links` (`create`, `list`, `get`, `rotate_secret`, `revoke`, `outbound.list/save/test/remove`) and `atlas_id_apps` grants (`list_apps`, `lookup`, `revoke_grant`). Platform: `platform.whoami`, `platform.keys` (`list`, `create`, `update`, `revoke`), `platform.audit.list` and `platform.audit.streams` (CRUD + `test`).
- **Privacy executor.** `privacy` (`discover`, `preset`, `lookup`, `create_request`, `get_request`, `cancel_request`, `orchestrator.get/set/delete`); `Atlas::Privacy.verify_orchestrator_call` (verifies a signed case call or `privacy_request.updated` / `.completed` webhook), `valid_idempotency_key?`, `privacy_event?`. Data subject requests document the new fields (`canonical_type`, `source`, `detail`, `case_id`, `external_case`, `trace_id`, `steps`, `retention`, `deletion_effective_at`) and the `restriction` / `rectification` types.
- **Integrations.** `integrations` (`list`, `get`, `set` / `delete` with `dry_run:`, `deliveries` with `trace`, `events_secret`, `atlas_id_tokens`, `report_verify_error`, `card`, `card_revoke_sessions`, `public_instance`) and the server-side mint `integrations.get_token(session_id, for: "referalli")` / `sessions.get_token(id, for:)` (`POST /v1/sessions/:id/integration_tokens/:integration`).
- **Webhook endpoints.** `webhooks.endpoints.get`, `put_by_url`, `redeliver`, `replay`, `test(id, wait:)`, `create(dry_run:)`, `list` with `metadata:` and `starting_after`; delivery log params `status`, `event_type`, `since`, `until`, `starting_after` (limit up to 1000); `webhooks.delivery_health` / `delivery_health` (`get`, `set_alert_contacts`), `meta.egress_ips`. `Atlas::Webhook.verify(url:, require_v2:)` checks `v2` signatures (HMAC over `id.ts.url.body`, so a delivery replayed to another URL fails) and ignores unknown versions.
- **Status.** `status.get`, `status.subscription` (`get`, `set`, `delete`, `rotate_feed`), `status.incidents`, `status.dependencies` (CRUD + `refresh`).
- **Notices, advisories, exports.** `notices` (`list`, `acknowledge`), `security_advisories` (`list`, `acknowledge`, `list_public`), `audit_exports` (CRUD, `test`, `rotate_secret`), `sub_processors.list`, `entitlements.get`, `integration_health` (`get`, `providers`), `embed` (`get`, `csp`), `openapi` (`diff`, `api_catalog`), `instance.unknown_fields_report`, `instance.preflight_filtered` (`min_severity`, `include_suppressed`), `messaging.get_channel`.
- **Platform apps.** `platform.apps.create(dry_run:)` / `update(dry_run:)` / `bulk_delete(metadata:, dry_run:)`, `list` with a `metadata:` filter, `create_secret_key`, `clone_config`; bodies take `external_ref` and `metadata`.
- **Referrals.** `referrals.install(preset)`; provider id `referalli` (the old `referally` still resolves: `Atlas::REFERRAL_PROVIDER_ALIASES`); `context_cookies`, `provider_aliases`, `capabilities`, `one_click`. Entitlement overrides carry `internal`.
- **Errors.** `INSUFFICIENT_SCOPE` (alias of `SCOPE_MISSING`, still tolerated: `APIError#insufficient_scope?`, `#required_scope`), `STEP_UP_REQUIRED` (`#step_up_required?`), `ROUTE_NOT_FOUND` with `#did_you_mean`, `#allowed_methods`, `#docs_url`, `PARTNER_LINK_UNAVAILABLE`, `NOT_A_LIVE_INSTANCE`, `TEST_MODE_ONLY`, `TESTING_UNAVAILABLE`.
- **Tracing and keys.** `Atlas::Client.new(key, traceparent:)` / `with_options(traceparent:)` send a W3C `traceparent` on every request; `Atlas::Trace` (`generate`, `parse`, `child`, `valid?`, `from_headers`). `Atlas::KeyFormat` recognises `atlas_<env>_<kind>_...` alongside `sk_` / `pk_` / `psk_` / `whsec_`.
- **Back-channel logout.** `Atlas::BackchannelLogoutApp`, a Rack endpoint that verifies the `logout_token` and answers 200 / 400 / 503 + `Retry-After`.
- **Constants.** New webhook event names (privacy, secret key, webhook endpoint and delivery target health, `webhook.test`, `status.incident.*`, `user.deletion_*`), `WEBHOOK_EVENT_NAMING`, `WEBHOOK_SIGNATURE_VERSIONS`, the new scopes and preflight codes.
- **Gap fixes.** OIDC relying parties: `Atlas::OIDC.organization_of` (`org_id`, `org_slug`, `org_role`, `org_permissions`), `organizations_of` (the `orgs` claim of the `organizations` scope, `Atlas::OIDC::SCOPE_ORGANIZATIONS`), `sso_of` (`sso_connection_id`, `sso_tenant_id`, `sso_issuer`, `sso_domain`) and `authorize_url_with_organization` (the `organization` authorize parameter). Partner link requests: `partner_links.requests` (`list`, `get`, `approve`, `deny`), `partner_links.set_certificates` (mTLS `cert_fingerprints`), `partner_links.outbound.request_link`; for a partner product `Atlas::PartnerLinkRequests.create` / `get` / `verify_delivery` (the signed `partner_link.credentials` / `partner_link.denied` delivery). Keys document `owner`, `expires_at` (default one year, never longer) and `allowed_origins`; `ORIGIN_NOT_ALLOWED` with `APIError#origin_not_allowed?`. Webhook replay and redelivery accept `since: "failing_since"` (`Atlas::WEBHOOK_REPLAY_SINCE_FAILING`); endpoints report `last_failing_since`. `Atlas::AtlasIdTokens.fetch` calls the browser route `POST /v1/client/integrations/:id/atlas_id_tokens` for Sign in with Atlas users (Bearer or DPoP).
- Lists on the new routes are cursor-paginated (`starting_after` / `next_cursor`), so `Atlas.paginate` works with them.

### Changed

- The referral provider is `referalli` throughout (`referally` is still accepted by the server).

### Not covered

- Sealed-box (`secret_recipient`) opening: it needs libsodium, which the gem does not depend on. Pass the recipient key and open `sealed_secret` with `rbnacl` or `libsodium`.
- Device-flow login helpers for CLIs: this SDK has no CLI.

## 0.16.0 — 2026-10-24

### Added

- **Policy acceptance.** `policies` (`list`, `create`, `get`, `update`, `delete`, `list_acceptances`, `export_acceptances_csv`, `for_user`) with `policies.versions` (`list`, `create`, `get`, `update`, `delete`, `publish`, `retire`) and `policies.settings` (`get`, `update`: the `pol` session claim), and `policy_source` (`get`, `update`, `delete`, `test`, `sync`, `list_deliveries`; the signing secret is write-only). `users.record_consent` / consent records carry the acceptance evidence (`policy_version_id`, `content_sha256`, `display`, `scrolled_to_end`, `view_ms`, `locale`).
- **Policy source helpers** for a CMS written in Ruby: `Atlas::PolicySourceProtocol.verify_feed_request(method:, path_and_query:, headers:, secret:)` checks Atlas's signed feed request (`atlas-id`, `atlas-timestamp` in ms, `atlas-signature` with one or more `v1,<base64 HMAC-SHA256>` values over `{id}.{ts}.GET\n{path+query}`, five-minute window) and returns the `key` Atlas asked for; `sign_event(event:, secret:)` signs a `policy.published` / `policy.retired` event for Atlas.
- `Atlas.policies(claims)` / `Atlas.accepted_policy_version(claims, key)` (and the same on `VerifyResult`) read the `pol` session claim. `WEBHOOK_EVENT_USER_POLICY_ACCEPTED`, `WEBHOOK_EVENT_POLICY_VERSION_PUBLISHED`.

## 0.15.0 — 2026-10-24

### Added

- **Migrate from Better Auth: sealed-bundle imports.** `better_auth_imports`: `get_public_key`, `rotate_public_key`, `create`, `list`, `get`, `upload_part` (text/plain), `finalize`, `dry_run`, `apply` (resumes a failed import), `delete`, `list_jwks`, `delete_jwk`. Helpers: `upload(bundle, options:, part_bytes:) { |n, of| }` creates the import, uploads the bundle in line-aligned parts of at most 8 MiB (`Atlas::Resources::BetterAuthImports.split_bundle_parts`, `PART_BYTES`) and finalizes it; `wait_for(id, interval:, timeout:) { |imp| }` polls until the import leaves `analyzing` / `queued` / `applying`.
- **Better Auth session bridge.** `better_auth_bridge.get` / `update` / `delete` (migration window, cookie prefix, live fallback; the old app's secret is write-only) and `better_auth_bridge.exchange(token, client_ip:, user_agent:, remember:)` on the secret-key Backend API route, forwarding the end user's IP and user agent (`X-Atlas-Client-IP`, `X-Atlas-Client-User-Agent`). `Atlas::BetterAuth.exchange` classifies the outcome (`:session`, `:needs_mfa`, `:refused` with `meta.bridge_outcome`; never raises). `Atlas::BetterAuth::Bridge` turns a request's cookies into a `Decision` (Atlas cookies to set, Better Auth cookies cleared only on a final refusal, `continuation_url` for a second factor). `Atlas::BetterAuth::RackMiddleware` (any Rack app) and, in Rails, `Atlas.configure { |c| c.better_auth_bridge = true }` (with `secret_key`) exchange a GET/HEAD's Better Auth cookie and redirect to the same URL signed in. The transport takes per-call `headers:` (never the authorization header).
- **Better Auth JWTs during the cutover.** `Atlas::Backend.new(..., legacy_issuers: [{ issuer:, until:, jwks: | jwks_url:, audience:, algorithms:, resolve_subject: }])` (and `c.legacy_issuers` in Rails): a token from that issuer, inside its window, is verified against that issuer's keys only (EdDSA, ES256, ES512, RS256, PS256; `exp` required) and its `sub` is mapped to the Atlas user id through `external_id` (Backend API lookup with `secret_key` / `bapi_base_url`, cached 5 minutes, at most 10 000 entries; failures are not cached). The claims carry `external_id` and `legacy`.

## 0.14.0 — 2026-10-24

### Added

- **DPoP (RFC 9449) on the access-token verifier.** A DPoP-bound token (`cnf.jkt`) is accepted only with the DPoP scheme and a valid proof (never as Bearer): `typ` `dpop+jwt`, `Atlas::DPoP::ALGS` (ES256/384/512, RS256/384/512, PS256/384/512, EdDSA), public embedded JWK, signature, `htm`, normalised `htu` (`Atlas::DPoP.normalize_htu`; `public_origin:` for path-only URLs), `iat` window, `ath`, `jti` replay via a pluggable store (`Atlas::DPoP::MemoryReplayStore` by default), RFC 7638 `Atlas::DPoP.jwk_thumbprint` match. `require_dpop:` refuses unbound tokens; `dpop_nonces:` (`Atlas::DPoP::HmacNonceSource`) demands a server nonce (`use_dpop_nonce`, `AccessTokenResult#dpop_nonce` for the `DPoP-Nonce` header). `verify(..., method:, url:, dpop:)` and `verify_rack(env)`; challenges use the `DPoP` scheme with `algs`. `Atlas::AccessTokenGuard` checks the proof against the Rack request and sets `dpop-nonce`. Metadata advertises `dpop_signing_alg_values_supported` and takes `dpop_bound_access_tokens_required:`.
- **Billing: several subscriptions per subject, add-ons, Chargebee / Autumn / Commet.** `billing.get_subscription`, `sync_plan_entitlements`, `get_settings` / `update_settings` (limit merge `max` / `sum`), `check_feature`; plans take `kind` (`base` / `addon`), `limits` and `seat_feature_id`; usage takes `feature` and `subscription_id`; provider config keys for `chargebee`, `autumn`, `commet` documented on `set_provider`. `Atlas::BILLING_PROVIDERS`.
- **Custom OAuth / OIDC providers.** `custom_oauth_providers`: `list`, `get`, `create`, `update`, `delete`, `discover`, `preview_profile_mapping` (ad hoc or `id:`), `list_signing_keys` / `rotate_signing_key` / `retire_signing_key`. OIDC SSO connections gain `preview_profile_mapping` and the same signing-key methods.
- **Actions gallery.** `action_gallery` (`list`, `get`, `install`, `installs`, `update`) and `action_templates` (`list`, `create`, `get`, `update`, `delete`, `add_version`, `submit_version`, `delete_version`, `publish`, `unlist`).
- **Session custom data.** `sessions.set_custom_data` (replace; `nil` clears) and `update_custom_data` (merge; `nil` removes a key). `Atlas::WEBHOOK_EVENT_SESSION_UPDATED`.
- **Sign-in settings.** `instance_security.set_wallet_rpc_secret(chain_id:, url:)`; rate-limit `rules` pass through `rate_limit_policy.update`; `instance.set_account_linking_trust`, `instance.set_captcha_config`; `Atlas::CAPTCHA_PROVIDERS` (incl. `captchafox`, `vercel_botid`), `Atlas::LINKING_TRUST_LEVELS`.
- **Vercel BotID attestations.** `Atlas::BotId.create_attestation(secret, is_bot:, verified_bot:, ttl_seconds:)` signs a verdict in Atlas's `atlas_botid.v1` format.
- **Enterprise SSO.** `sso_connections.get_saml_encryption_key`, `create_saml_encryption_key` (create or rotate), `retire_previous_saml_encryption_key`, `delete_saml_encryption_key`; the SAML Single Logout and encrypted-assertion fields pass through create/update. Attack protection `dormant_accounts`; `Atlas::WEBHOOK_EVENT_USER_REACTIVATED`; `Atlas::EMAIL_TEMPLATE_ACCOUNT_REACTIVATED`.
- **Atlas as OAuth provider.** `instance_security.get_signing_key_provider` / `set_signing_key_provider` / `remove_signing_key_provider` (AWS KMS, Google Cloud KMS, Azure Key Vault); OAuth client `access_token_format` / `token_lifetimes` and resource-server `access_token_format`, refresh lifetimes and `introspection_client_ids` pass through. `Atlas::SIGNING_KEY_PROVIDERS`.
- **Opaque access tokens.** `AccessTokenVerifier.new(introspection: { client_id:, client_secret:, ... })` validates non-JWT access tokens at Atlas's RFC 7662 endpoint, cached by token hash (TTL, negative TTL, never past `exp`, bounded); `introspect_jwts: true` checks JWTs live too. `Atlas::Introspector`.
- **Device sign-in approval.** `Atlas::DeviceAuthorizations.new(frontend_api:, session_token:)`: `lookup`, `approve`, `deny` with the user's session token; `Error#needs_reverification?` / `#invalid_code?`; `format_user_code`, `user_code_from_url`.

### Changed

- Without `introspection:`, a token that is not a JWT is refused with "configure `introspection` to accept opaque tokens" instead of "malformed".

## 0.13.0 — 2026-10-23

### Added

- **App roles.** `client.app_roles`: `list`, `create`, `get`, `update`, `delete`, `list_users`, `get_for_user`, `set_for_user` (replace, or add/remove), `remove_from_user`. `Atlas.has_app_role?` / `Atlas.has_app_permission?` and the `app_role:` / `app_permission:` conditions of `has?` / `protect` read the `app_roles` / `app_permissions` claims (no active organization needed).
- **Organization teams and custom roles.** `organizations.teams` (list, create, get, update, delete, members list/add/remove) and `organizations.roles` (the roles an org can assign; create/update/delete its own, `reassign_to:`). `organizations.get_by_slug`, `organizations.check_slug`, `organizations.invitations.resend`.
- **User search and timed bans.** `users.list` documents the search filters (`query`, `email_address`, `username`, `phone_number`, `external_id`, `banned`, `email_verified`, `organization_id`, `created_after` / `created_before`, `order_by`, `offset`, `include_total_count`); `users.ban(id, { reason:, note:, expires_in_seconds:, expires_at: })`.
- **API key controls.** Create and update bodies take `enabled`, `rate_limit`, `remaining`, `prefix`, `expires_in_seconds`; `api_keys.verify` takes `required_scopes` and a refusal of a live key carries `code` (`insufficient_scope`, `rate_limited`, `usage_exhausted`).
- **Billing providers (bring your own key).** `billing.list_providers`, `get_provider`, `set_provider`, `test_provider`, `delete_provider(force:)`; `billing.change_subscription`, `cancel_subscription(immediately:)`, `restore_subscription`. Plans take `provider`, `provider_price_id`, `annual_price_id`, `annual_amount`.
- **OAuth server administration.** `instance_security.list_signing_keys` / `rotate_signing_key` (`alg` RS256 or ES256); `client.oauth_initial_access_tokens` (list, create, revoke). OAuth clients take `disabled`, `require_pkce`, `subject_type`, `sector_identifier_uri`, `secret_expires_in_seconds`; resource servers take `signing_alg` and `publish_resource_metadata`.
- **Access-token verification for your API.** `Atlas::AccessTokenVerifier` checks an Atlas-issued OAuth access token locally (issuer, expiry, `token_use`, audience, scopes) and returns the RFC 6750 / RFC 9728 `WWW-Authenticate` challenge on refusal; the `Atlas::AccessTokenGuard` Rack middleware; `Atlas.build_www_authenticate`, `Atlas.protected_resource_metadata`, `Atlas.protected_resource_metadata_path`. DPoP-bound tokens are refused.
- `scim_tokens.update`, `user_hooks.list_before_user_create_calls`, `referrals.get_call`.

### Changed

- Session and logout-token verification accept **ES256** as well as RS256 (`Atlas::SIGNING_ALGS`), and nothing else.

## 0.12.0

### Added

- Referral settings carry browser capture: `browser_sources` (the referral programs whose script or cookie the browser reads; null on update resets to the provider's default), `browser_sources_default`, and `consent_provider` (`auto`, one consent manager, or `app`).

## 0.11.0

### Added

- **Two-way referral sync.** Referral settings carry two-way sync: `inbound` (`url`, `secret_set`, `endpoint_id`, `last_event`) on reads, write-only `inbound_secret` and `inbound_endpoint_id` on updates (null clears), and provider capability `inbound`.

## 0.10.0

- **Referral attribution v2.** `referrals.retry_failed(body = {}, idempotency_key: nil)` (`POST /v1/instance/referrals/calls/retry_failed`; `kind`, `error_code`; returns `requeued`), `referrals.simulate(code: nil)` (`POST /v1/instance/referrals/simulate`; `call_id`, `customer_ref`, `result`, `response`, `error`), `referrals.backfill(body, idempotency_key: nil)` and `referrals.get_backfill(id)` (`POST /v1/instance/referrals/backfill`, `GET /v1/instance/referrals/backfill/:id`; body `since`, `codes`, `code_metadata_path`; job `users_scanned`, `users_skipped`, `calls_queued`, `truncated`, `next_since`, `calls`), and `referrals.get_for_user(user_id)` (`GET /v1/users/:id/referral`).
- **Settings.** The referral settings gain `tracking_token`, `code_lookup_url`, `signup_code_field`, `forward_lifecycle`, `mirror_to_public_metadata` and `include_referral_claims` (read and write). `provider` can be `referalli`. Provider capabilities gain `alias`, `user` and `ping`. `connection` gains `last_ping` and `alert` (`signature_rejected` or `connection_paused`). `referrals.test` returns `method` (`ping` or `probe`), `ping` and `warnings`.
- **Call log.** `list_calls` takes `error_code` and `starting_after`; `limit` goes up to 1000. Kinds add `alias`, `user` and `ping`; calls carry `latency_ms`, `error_code`, `response`, `highlights`, `request_id` and `batch_id`.
- **Users.** New `users.set_external_id(id, external_id)` (`PATCH /v1/users/:id`; `nil` clears; with referrals on, the change is forwarded to the platform as an alias). The user `referral` gains `partner_external_ref`, `referral_status` and `notes`. New event `user.referral_resolved` (`data` is the full user).
- **before_user_create hook.** New `user_hooks` namespace: `get_before_user_create`, `update_before_user_create(body, idempotency_key: nil)` and `test_before_user_create` (`/v1/instance/hooks/before_user_create`). The hook call is signed like a webhook with type `user.before_create`; verify it with `Atlas::Webhook.verify`.
- **Preflight** can report `referrals_secret_invalid`, `referrals_program_inactive`, `referrals_unreachable`, `referrals_clock_skew` and `referrals_external_id_unset`.
- **Changed on the server.** `referral["status"]` is now where attribution stands (`pending`, `attributed`, `none`, `failed`, `held`, `flagged`); the platform's own status moved to `referral_status`. `user.created` carries `status: "pending"` while the platform has not answered.
- Compatible: new methods only.

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
