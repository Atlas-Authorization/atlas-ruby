# Atlas Ruby SDK

The official **Ruby backend SDK** for [Atlas](https://atlasauth.net) — a typed client over the `sk_` Backend API (BAPI), plus local session-token verification. It is the Ruby peer of the TypeScript `@atlasauth/backend` and Python `atlas-backend` SDKs and covers the whole Backend API and the platform-key API.

> This is a **server-side** SDK. It uses your instance **secret key** (`sk_...`) and must never ship to a browser or mobile app. For client-side sign-in flows use the JS, Swift, Kotlin, or Flutter SDKs.

## Install

```ruby
# Gemfile
gem "atlas-auth"
```

```sh
bundle install
# or
gem install atlas-auth
```

Requires Ruby 3.0+. The only runtime dependency is [`jwt`](https://rubygems.org/gems/jwt) (for session-token verification); everything else is standard library.

## Quickstart

```ruby
require "atlas"

atlas = Atlas::Client.new(ENV.fetch("ATLAS_SECRET_KEY")) # "sk_live_..."

# Create a user
user = atlas.users.create(email_address: "ada@example.com", password: "•••••••")

# Read one, list many
atlas.users.get(user["id"])
page = atlas.users.list(limit: 20)

# Walk every page of a cursor-paginated list
Atlas.paginate(atlas.organizations).each { |org| puts org["name"] }
all_users = Atlas.collect(atlas.users, status: "active")
```

### Configuration

```ruby
Atlas::Client.new(
  "sk_live_...",
  api_url: "https://api.atlasauth.net", # default: https://api.atlasauth.net
  open_timeout: 30,
  read_timeout: 30,
)
```

Every request is authenticated with `Authorization: Bearer <secret_key>`; the key is never logged or placed in a URL.

### Idempotency

Write operations accept an `idempotency_key:` so a retried request is applied at most once:

```ruby
atlas.users.create({ email_address: "ada@example.com" }, idempotency_key: "signup-42")
```

### Strict request bodies

By default a write that includes a field the endpoint does not accept still succeeds; the field is ignored and named in the `Atlas-Unknown-Fields` response header. Turn on strict bodies to have such a write refused instead (422 `UNKNOWN_FIELD`, with `param` naming the field), and/or get told about ignored fields:

```ruby
atlas = Atlas::Client.new(
  ENV.fetch("ATLAS_SECRET_KEY"),
  strict: true,                                                  # sends Atlas-Strict: true on every write
  on_unknown_fields: ->(w) { Rails.logger.warn("Atlas ignored #{w.fields.join(', ')} on #{w.method} #{w.path}") },
)

# Override for one call (or a block of calls):
atlas.with_options(strict: false).users.update("user_123", { legacy_field: "x" })
```

`strict: false` sends `Atlas-Strict: false`, which opts a request out of an instance-wide strict default.

## Errors

Any non-2xx response raises a typed `Atlas::APIError` carrying the HTTP status and the full `{ errors: [...] }` envelope. Status codes map to subclasses so you can rescue precisely:

```ruby
begin
  atlas.users.get("user_missing")
rescue Atlas::NotFoundError => e
  e.status      # => 404
  e.code        # => "NOT_FOUND"   (first error's stable code)
  e.errors      # => [{ "code" => "NOT_FOUND", "message" => "..." }]
rescue Atlas::APIError => e
  # BadRequestError, AuthenticationError, PermissionError, ConflictError,
  # RateLimitError, ServerError, ... all inherit from APIError.
end
```

`Atlas::ErrorCode` names the codes most worth branching on: `UNKNOWN_FIELD`, `EMAIL_DELIVERY_NOT_CONFIGURED`, `EMAIL_PROVIDER_REQUIRED`, `EMAIL_PROVIDER_IN_USE`, `PLAN_IN_USE`, `WRONG_KEY_SURFACE`, `INVALID_KEY` and more:

```ruby
rescue Atlas::UnprocessableEntityError => e
  notify_admin if e.has_code?(Atlas::ErrorCode::EMAIL_DELIVERY_NOT_CONFIGURED)
```

## Check your setup

```ruby
report = atlas.instance.preflight
unless report["ok"]
  report["findings"].each do |f|
    puts "#{f['severity']} #{f['code']}: #{f['message']}\n  fix: #{f['fix']}"
  end
end
```

## Sign-in page design

```ruby
# Upload an image (PNG, JPEG, GIF or WebP; the type is detected from the bytes)
asset = atlas.design.upload_asset(File.binread("hero.jpg"), kind: "background")

atlas.design.update(
  preset: "glass",
  palette: { primary: "#4f46e5" },
  background: { image: { assetId: asset["asset_id"], fit: "cover" } },
)
atlas.design.preview({ preset: "midnight" })        # compile without saving
atlas.organizations.update_design("org_123", { palette: { primary: "#0f766e" } })
atlas.design.catalog                                 # presets, fonts, CSS variables
```

`Atlas::Resources::Design` documents every design section and its allowed values.

## Cookie consent

```ruby
atlas.instance.set_cookie_consent(script_url: "https://cmp.example.com/loader.js", site_id: "abc123")
atlas.instance.get_cookie_consent
atlas.instance.delete_cookie_consent
```

Add a "Cookie settings" link to the hosted pages with `settings_link` (`nil` or omitted means no link). It needs a `preset` (`Atlas::Resources::Instance::COOKIE_CONSENT_PRESETS`: `cookiemunch`, `cookiebot`, `onetrust`, `custom`) or at least one attribute:

```ruby
consent = atlas.instance.set_cookie_consent(
  script_url: "https://consent.cookiebot.com/uc.js",
  settings_link: { label: "Cookie settings", preset: "cookiebot", attributes: { "class" => "footer-link" } }
)
consent["settings_link"]["rendered_attributes"]  # your attributes plus the preset's trigger
```

## Messaging providers

Removing the email provider is refused (`Atlas::ConflictError` with `EMAIL_PROVIDER_IN_USE`) while email-dependent features are on and nothing else would deliver email; `meta["features"]` lists them. Pass `force: true` to remove it anyway:

```ruby
begin
  atlas.messaging.delete_channel("email")
rescue Atlas::ConflictError => e
  raise unless e.has_code?(Atlas::ErrorCode::EMAIL_PROVIDER_IN_USE)
  e.errors.first["meta"]["features"]  # => ["emailCode", "passwordReset"]
  atlas.messaging.delete_channel("email", force: true)
end
```

## OAuth clients

For a first-party client, `skip_logout_confirmation: true` lets RP-initiated logout with an exactly registered `post_logout_redirect_uri` end the session and redirect straight back, without the confirmation page:

```ruby
atlas.oauth_clients.update("oc_123", { skip_logout_confirmation: true })
```

Rotating a client secret keeps the previous one working for `overlap_seconds` (default 24 hours, at most 7 days), so you can deploy the new secret without downtime. Pass `0` to revoke the old one now, for example after a leak:

```ruby
rotated = atlas.oauth_clients.rotate_secret("oc_123", { overlap_seconds: 3600 })
rotated["client_secret"]               # shown once
rotated["previous_secret_expires_at"]  # epoch ms, or nil when the old secret already stopped
```

## Platform API: Sign in with Atlas apps

Construct the client with a **platform key** (`psk_...`) to manage apps for your account:

```ruby
platform = Atlas::Client.new(ENV.fetch("ATLAS_PLATFORM_KEY")).platform

app = platform.atlas_id_apps.create(
  name: "Acme",
  redirect_uris: ["https://acme.com/auth/callback"],
  post_logout_redirect_uris: ["https://acme.com/"],
  backchannel_logout_uri: "https://acme.com/auth/backchannel-logout",
  branding: { theme: "auto", accent_color: "#4f46e5", copy: { sign_in_title: "Sign in to {app}" } },
)
app["client_secret"]                                 # shown once (confidential apps)

platform.atlas_id_apps.rotate_secret(app["id"])
asset = platform.design_assets.upload(File.binread("logo.png"), kind: "logo")
platform.atlas_id_apps.update(app["id"], { branding: { design: { logo: { assetId: asset["asset_id"] } } } })
platform.apps.list                                   # apps (instances) your platform provisions
```

## Domain moves, logout fan-out and managed email

```ruby
# Move every URL from the old origin to the new one. dry_run first shows the diff.
preview = atlas.instance.move_origin({ from: "https://old.example.com", to: "https://example.com", dry_run: true })
preview["changes"].each { |c| puts "#{c['object']} #{c['field']}: #{c['before']} -> #{c['after']}" }

# Send the same logout_token your OIDC apps get to another service.
atlas.logout_notify_endpoints.create({ url: "https://api.example.com/atlas/logout" })

# Set your domain up on your own Resend or Brevo account, then publish the returned DNS records.
managed = atlas.messaging.create_managed_email({ from_address: "Acme <no-reply@example.com>", transport: "resend", config: { api_key: ENV.fetch("RESEND_API_KEY") } })
puts managed["records"]

# A development instance can send sign-in emails through your provider without a verified domain.
atlas.messaging.enable_development_email({ provider_id: "mp_123" })
atlas.messaging.disable_development_email
```

With a platform key, `platform.atlas_id_apps.find_users(id, email)` answers a privacy request for one app,
`revoke_grant(id, grant_id)` revokes one person's approval, and `platform.atlas_id_publisher` claims and verifies
the publisher name shown on consent screens.

## Webhooks

`Atlas::Webhook.verify` accepts an `atlas-signature` header that carries several signatures separated by spaces (`v1,<sig> v1,<sig>`). While an endpoint secret rotates, Atlas may sign each delivery with the old and the new secret; the delivery verifies when any one signature matches.

A rotation stops the old secret at once by default. Pass `overlap_seconds` (at most 7 days) to keep it signing each delivery next to the new one while you deploy; choose an overlap only once every receiver accepts several signatures:

```ruby
rotated = atlas.webhooks.endpoints.rotate_secret("whep_123", { overlap_seconds: 3600 })
rotated["previous_secret_expires_at"]  # epoch ms, or nil when the old secret already stopped
```

## Trusted reverse proxy

If a reverse proxy serves the Frontend API from your own origin, give it a proxy secret. It sends the secret in `X-Atlas-Proxy-Secret` and the browser's IP in `X-Atlas-Client-IP`; Atlas then uses that IP for rate limits, lockout, risk signals and audit logs.

```ruby
created = atlas.instance_security.create_proxy_secret
created["secret"]                                   # shown once; store it in your proxy's environment
atlas.instance_security.get_proxy_secret            # set, created_at, previous_expires_at (never the secret)
atlas.instance_security.create_proxy_secret({ overlap_seconds: 3600 }) # rotate; the old one works 1 hour
atlas.instance_security.delete_proxy_secret
```

Platform rotations take an overlap too: `platform.apps.rotate_instance_secret(app_id, instance_id, { overlap_seconds: 0 })` (default 72 hours), `platform.atlas_id_apps.rotate_secret(id, { overlap_seconds: 3600 })` (default 24 hours) and `platform.atlas_id_apps.rotate_webhook_secret(id, { overlap_seconds: 3600 })` (default 0).

## Referral attribution

With referral attribution on, Atlas reports every interactive sign-up to your referral platform before
`user.created` is sent. Users carry `referral` (where attribution stands and, once attributed, who referred them;
`nil` when never reported), `referral_code` and `referral_link`. `referral["status"]` is `pending`, `attributed`,
`none`, `failed`, `held` or `flagged`; the platform's own status is `referral["referral_status"]`.

```ruby
atlas.referrals.update({
  enabled: true,
  provider: "webhook", # the Atlas referral protocol; or "referalli" or another built-in adapter
  endpoint_url: "https://referrals.example.com/atlas",
  signing_secret: ENV.fetch("REFERRAL_SIGNING_SECRET"),
  security: { on_high_risk: "hold" }
})
atlas.referrals.test                                   # { "ok" => true, "http_status" => 404, ... }
failed = atlas.referrals.list_calls(status: "failed", limit: 20)
atlas.referrals.retry_call(failed["data"].first["id"])

atlas.users.update("user_123", { referral_code: "ada-1" }) # 409 REFERRAL_CODE_TAKEN if held
atlas.users.flag_referral("user_123", reason: "self-referral")

atlas.referrals.simulate(code: "ACME10")                     # a made-up user; nothing is stored
atlas.referrals.retry_failed({ error_code: "signature_rejected" }) # after pasting the new secret
atlas.referrals.list_calls(limit: 1000, starting_after: "rfc_123", error_code: "timeout")
job = atlas.referrals.backfill({ since: "2026-01-01", code_metadata_path: "public_metadata.referral_code" })
atlas.referrals.get_backfill(job["id"])                      # running, then completed
atlas.referrals.get_for_user("user_123")                     # the stored result, no call to the platform
atlas.users.set_external_id("user_123", "cust_42")           # forwarded to the platform as an alias
```

Enabling without what the provider needs is `422 REFERRALS_NOT_CONFIGURED`. When the platform has not answered by the
time `user.created` is sent, `referral["status"]` is `pending` and the `user.referral_resolved` webhook follows with the
final user (`attributed`, `none` or `failed`). `user.referral_attributed` still fires for a late attribution.

Two-way sync: a provider with the `inbound` capability sends referral changes made after sign-up back to Atlas. The
settings report `inbound` (`url` to give the platform, `secret_set`, `endpoint_id`, and `last_event` with `at`, `type`,
`outcome`). Send `inbound_secret` (write-only, 16-512 characters) to store the platform's event secret and
`inbound_endpoint_id` for its subscription id; `nil` clears either.

Browser capture: `browser_sources` lists the referral programs whose script or cookie the browser reads (`nil` goes
back to the provider's default, reported by `browser_sources_default`), and `consent_provider` picks the consent
manager that decides (`auto`, one manager, or `app`).

To give each user your own id before the first referral call, turn on the `before_user_create` hook. Atlas then sends
your endpoint a signed `POST` (verify it with `Atlas::Webhook.verify`) of type `user.before_create` for every
self-service sign-up, and stamps the `external_id` and metadata you answer:

```ruby
atlas.user_hooks.update_before_user_create({
  enabled: true,
  url: "https://app.example.com/hooks/before-create",
  signing_secret: ENV.fetch("BEFORE_CREATE_SECRET")
})
atlas.user_hooks.test_before_user_create # { "ok" => true, "answer" => { ... } }
```

## Back-channel logout

When a user signs out, Atlas POSTs a signed `logout_token` to your app's `backchannel_logout_uri` (Sign in with Atlas apps and session-exchange apps). Verify it, end the matching local sessions, and answer 200:

```ruby
LOGOUT = Atlas::BackchannelLogout.new(
  issuer:    "https://atlasauth.net",                       # your instance's frontend API origin for session-exchange apps
  jwks_url:  "https://atlasauth.net/.well-known/jwks.json",
  client_id: ENV.fetch("ATLAS_CLIENT_ID"),                  # the token's audience
  jti_store: Atlas::MemoryJtiStore.new,                     # optional: refuse replays (use a shared store with several processes)
)

# Any Rack app (Rails, Sinatra, Roda, ...): POST /auth/backchannel-logout
def backchannel_logout(env)
  request = Rack::Request.new(env)
  claims = LOGOUT.verify(request.POST["logout_token"])
  if claims.sid
    Session.where(atlas_sid: claims.sid).destroy_all       # one session
  else
    Session.where(atlas_user_id: claims.sub).destroy_all   # every session of the user
  end
  [200, { "cache-control" => "no-store" }, []]
rescue Atlas::InvalidLogoutTokenError
  [400, { "cache-control" => "no-store" }, []]
end
```

The verifier checks the RS256 signature, `iss`, `aud`, `iat`, `exp`, `jti`, the back-channel logout `events` claim, that `sid` or `sub` is present, that there is no `nonce`, and the `logout+jwt` type. To refuse replays across processes, pass any object with `add?(jti, ttl_seconds)` that returns `false` for a `jti` it has seen (for example Redis `SET key 1 NX EX ttl`).

## Session-token verification

Verify Atlas session JWTs **locally** — no round trip per request. The JWKS is cached in-process with kid-miss refetch throttled to once per minute.

```ruby
backend = Atlas::Backend.new(
  jwks_url: "https://api.atlasauth.net/v1/jwks",
  issuer:   "https://your-instance.atlasauth.net",
  authorized_parties: ["https://app.example.com"], # optional azp allowlist
)

result = backend.verify(session_jwt)
if result.ok?
  result.claims["sub"]                          # the user id
  result.protect(permission: "org:billing:manage")
else
  result.reason                                 # :invalid, :malformed, :no_keys, :unauthorized_party
end

# From a request's headers (Authorization: Bearer <jwt> or the __session cookie):
backend.authenticate_request(request.headers)
```

`verify` is the fast local path. `verify_online` asks Atlas whether the session is still live (a round trip; fails closed on an outage).

### Rails

Wire a shared client in an initializer:

```ruby
# config/initializers/atlas.rb
ATLAS = Atlas::Client.new(Rails.application.credentials.atlas_secret_key)
BACKEND = Atlas::Backend.new(
  jwks_url: "https://api.atlasauth.net/v1/jwks",
  issuer:   "https://your-instance.atlasauth.net",
)
```

Then verify in a `before_action` and branch on `BACKEND.authenticate_request(request.headers)`.

## API key spend caps

Give an end-user API key caps in your own units, then meter what your API consumed against them. A refused debit records nothing and is not an error, so you enforce it inside your own transaction:

```ruby
key = atlas.api_keys.create({
  subject_type: "user", subject_id: "user_123", name: "CI",
  limits: [
    { unit: "requests", amount: 10_000, period: "day" },   # day/month are UTC calendar windows
    { unit: "usd_cents", amount: 500, period: "request" }  # caps a single debit; "total" never resets
  ],
})

debit = atlas.api_keys.record_usage(key["id"], amount: 1, unit: "requests", idempotency_key: request_id)
unless debit["allowed"]                     # debit["code"] == Atlas::ErrorCode::LIMIT_EXCEEDED
  halt 429, "quota exceeded (resets #{debit['exceeded'][0]['resets_at']})"
end

atlas.api_keys.get_usage(key["id"])         # caps with used/remaining/resets_at + raw counters
atlas.api_keys.update(key["id"], { limits: nil })  # remove every cap
```

Reusing an `idempotency_key` replays the first outcome (`idempotent_replay: true`) without counting again; reusing it with a different unit or amount raises `Atlas::ConflictError` with `IDEMPOTENCY_CONFLICT`. `api_keys.verify` also returns the key's `name`, `scopes`, `constraints`, `limits` and `usage`. Subscribe to the `api_key.created`, `api_key.updated` and `api_key.limit_reached` webhooks to mirror keys and react to a filled cap.

## Session keep-alive

If your app loads Atlas on only some pages, keep the session's inactivity window moving from your backend:

```ruby
session = atlas.sessions.touch(session_id)
session["extended"]         # false when a touch within the last minute already moved it
session["idle_expires_at"]  # epoch ms the session ends from inactivity
```

It never extends past the absolute expiry and never revives an ended session (`Atlas::ConflictError` with `SESSION_REVOKED`, `SESSION_IDLE_EXPIRED` or `SESSION_EXPIRED`). Calling it on every request is safe.

`users.create` and `import_export.import_users` accept `notify: false` (the default), which guarantees the user is sent no email, SMS or push as a consequence of the create.

## Policy acceptance

Terms of Service, privacy policies and any other policy your users accept at sign-up (and again
at sign-in when a new version takes effect). A version goes draft, published (with an
`effective_at`), retired; each acceptance is kept as evidence.

```ruby
atlas.policies.create({ key: "tos", title: "Terms of Service", applies_to: "sign_in_and_sign_up" })
atlas.policies.versions.create("tos", { version: "2026-10-24", content_markdown: "# Terms\n..." })
atlas.policies.versions.publish("tos", "2026-10-24", { effective_at: "2026-11-01T00:00:00Z" })
atlas.policies.list_acceptances("tos", { version: "2026-10-24", limit: 50 })
csv = atlas.policies.export_acceptances_csv("tos")
atlas.policies.for_user("user_123")                      # standing on every policy, incl. needs_acceptance
atlas.policies.settings.update({ session_claim: true })  # put `pol` on session tokens
```

With the session claim on, `Atlas.policies(claims)` / `Atlas.accepted_policy_version(claims, "tos")`
(and the same two methods on a `VerifyResult`) read the `pol` claim. The `user.policy_accepted`
and `policy.version_published` webhook events have the constants
`Atlas::WEBHOOK_EVENT_USER_POLICY_ACCEPTED` and `Atlas::WEBHOOK_EVENT_POLICY_VERSION_PUBLISHED`.
`users.record_consent` takes the acceptance evidence (`policy_version_id`, `content_sha256`,
`display`, `scrolled_to_end`, `view_ms`, `locale`).

### Serving policies from your own system (policy source)

Point Atlas at a CMS or service with `atlas.policy_source.update(enabled: true, endpoint_url: ...,
signing_secret: ...)` (the secret is write-only), then `test` / `sync`. In your service, verify
Atlas's signed `GET {endpoint}/policies[?key=...]` and answer a feed:

```ruby
v = Atlas::PolicySourceProtocol.verify_feed_request(
  method: request.request_method, path_and_query: request.fullpath, headers: request.headers, secret: secret
)
return head(:unauthorized) unless v.verified?
render json: { object: "policy_list", policies: build_policies(only: v.key) }

# When a policy changes, tell Atlas (it re-fetches; nothing in the event is trusted as content):
signed = Atlas::PolicySourceProtocol.sign_event(event: { type: "policy.published", key: "tos", version: "2026-10-24" }, secret: secret)
Net::HTTP.post(URI(webhook_url), signed.body, { "content-type" => "application/json" }.merge(signed.headers))
```

## Integrator platform (0.17)

```ruby
atlas = Atlas::Client.new(ENV.fetch("ATLAS_SECRET_KEY"), traceparent: Atlas::Trace.generate)
atlas.whoami.get                                   # the key in use: kind, scopes, expiry
key = atlas.secret_keys.create({ name: "ci", scopes: ["users:read"] })   # key["secret"] is shown once
atlas.privacy.lookup({ emails: ["ada@example.com"] })                     # data-rights executor (privacy:execute)
atlas.integrations.get_token("sess_123", for: "referalli")                # server-side integration token
atlas.integrations.get_token("sess_123", for: "acme", audience_params: { tenant: "t1" }) # per-call audience (needs per_call_audience)
atlas.partner_platforms.registration("acme-consent")                      # this instance as a partner platform
atlas.partner_platforms.store_token("acme-consent", partner_token)        # write-only, never returned
atlas.users.list(include_deleted: true)                                   # soft-deleted users too
atlas.webhooks.endpoints.test("we_1", wait: 10)
atlas.platform.apps.create({ external_ref: "crm-42", metadata: { team: "a" } }, dry_run: true)
```

Verify a webhook that also signs the URL (`signature_versions` including `v2`) with
`Atlas::Webhook.verify(body:, headers:, secret:, url: endpoint_url)`. Any `sk_` / `psk_` check should
accept the new `atlas_<env>_<kind>_...` form too: `Atlas::KeyFormat.secret_key?(key)`. Mount
`Atlas::BackchannelLogoutApp.new(logout: verifier) { |claims| ... }` for back-channel logout.
`INSUFFICIENT_SCOPE` replaces `SCOPE_MISSING`; use `error.insufficient_scope?` to match both.

Partner links need no pasted key: a partner calls `Atlas::PartnerLinkRequests.create(...)`, you
`approve` or `deny` it with `atlas.partner_links.requests`, and Atlas delivers the credentials to the
partner's callback, which checks them with `Atlas::PartnerLinkRequests.verify_delivery`. Secret keys
take `owner`, `expires_at` (one year by default, never longer) and `allowed_origins` (a call from another
browser origin is refused with `ORIGIN_NOT_ALLOWED`: `error.origin_not_allowed?`). Replay what an endpoint
missed with `atlas.webhooks.endpoints.replay(id, { since: "failing_since" })`. For OIDC relying parties,
`Atlas::OIDC.organization_of(claims)`, `organizations_of` (scope `organizations`) and `sso_of` read the
`org_*`, `orgs` and `sso_*` claims. `Atlas::AtlasIdTokens.fetch(...)` is the browser
`atlas_id_tokens` route for Sign in with Atlas users.

## Resources

Every Backend API operation is available on the client: `users`, `sessions`, `organizations` (with `memberships`, `invitations`, `domains`, `group_roles`, `audit_streams`, `end_users`, `reader_domain`, settings, design and branding), `roles`, `permissions`, `oauth_clients`, `resource_servers`, `sso_connections`, `scim_tokens`, `scim_provisioning`, `domains`, `waitlist`, `allowlist`, `blocklist`, `attack_protection`, `actor_tokens`, `invitations`, `webhooks`, `sign_in_tokens`, `audit_logs`, `audit_events`, `jwt_templates`, `api_keys`, `oauth_providers`, `sso_onboarding`, `fga`, `openfga`, `rate_limit_policy`, `risk_based_mfa`, `bot_signals`, `network_acls`, `managed_waf`, `log_streams`, `branding`, `design`, `email_templates`, `sms_templates`, `localizations`, `actions`, `billing`, `messaging`, `import_export`, `data_subject_requests`, `radius_clients`, `lti_platforms`, `instance` (incl. `preflight` and cookie consent), `instance_security`, `tokens`, `email_addresses`, `organization_settings_schema`, `entitlement_overrides`, `machines` (incl. enrolment tokens), `connectors`, `directory`, `diagnostics`, `config_changelog`, `events`, `usage`, `legacy_auth_connection`, `mcp`, `mcp_connector`, `notifications` (with `categories` and `templates`), `org_ldap_connections`, `policies` (with `versions` and `settings`), `policy_source`, `pca`, `redirect_urls`, `session_exchange_apps`, `tickets`, `captcha`, `whoami`, `secret_keys`, `keys`, `partner_links`, `partner_platforms`, `privacy`, `integrations`, `status`, `notices`, `security_advisories`, `audit_exports`, `sub_processors`, `entitlements`, `integration_health`, `embed`, `openapi`, `delivery_health`, `meta`, `testing` (development-instance helpers), and `platform` (`apps`, `atlas_id_apps`, `design_assets`; needs a platform key).

Anything not wrapped yet can be called directly: `atlas.transport.request(method: :get, path: "/v1/...")`.

## Development

```sh
bundle install
rake test        # or: ruby -Ilib -Itest test/client_test.rb
```

## License

MIT
