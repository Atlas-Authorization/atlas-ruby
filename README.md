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

# Send email from your own domain through Atlas, then publish the returned DNS records.
managed = atlas.messaging.create_managed_email({ from_address: "Acme <no-reply@example.com>" })
puts managed["records"]
```

With a platform key, `platform.atlas_id_apps.find_users(id, email)` answers a privacy request for one app,
`revoke_grant(id, grant_id)` revokes one person's approval, and `platform.atlas_id_publisher` claims and verifies
the publisher name shown on consent screens.

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

## Resources

Every Backend API operation is available on the client: `users`, `sessions`, `organizations` (with `memberships`, `invitations`, `domains`, `group_roles`, `audit_streams`, `end_users`, `reader_domain`, settings, design and branding), `roles`, `permissions`, `oauth_clients`, `resource_servers`, `sso_connections`, `scim_tokens`, `scim_provisioning`, `domains`, `waitlist`, `allowlist`, `blocklist`, `attack_protection`, `actor_tokens`, `invitations`, `webhooks`, `sign_in_tokens`, `audit_logs`, `audit_events`, `jwt_templates`, `api_keys`, `oauth_providers`, `sso_onboarding`, `fga`, `openfga`, `rate_limit_policy`, `risk_based_mfa`, `bot_signals`, `network_acls`, `managed_waf`, `log_streams`, `branding`, `design`, `email_templates`, `sms_templates`, `localizations`, `actions`, `billing`, `messaging`, `import_export`, `data_subject_requests`, `radius_clients`, `lti_platforms`, `instance` (incl. `preflight` and cookie consent), `instance_security`, `tokens`, `email_addresses`, `organization_settings_schema`, `entitlement_overrides`, `machines` (incl. enrolment tokens), `connectors`, `directory`, `diagnostics`, `config_changelog`, `events`, `usage`, `legacy_auth_connection`, `mcp`, `mcp_connector`, `notifications` (with `categories` and `templates`), `org_ldap_connections`, `pca`, `redirect_urls`, `session_exchange_apps`, `tickets`, `captcha`, `testing` (development-instance helpers), and `platform` (`apps`, `atlas_id_apps`, `design_assets`; needs a platform key).

Anything not wrapped yet can be called directly: `atlas.transport.request(method: :get, path: "/v1/...")`.

## Development

```sh
bundle install
rake test        # or: ruby -Ilib -Itest test/client_test.rb
```

## License

MIT
