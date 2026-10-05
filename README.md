# Atlas Ruby SDK

The official **Ruby backend SDK** for [Atlas](https://atlasauth.net) — a typed client over the `sk_` Backend API (BAPI), plus local session-token verification. It is the Ruby peer of the TypeScript `@atlasauth/backend` and Python `atlas-backend` SDKs and covers the full management surface (all 45 resource namespaces).

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

## Session-token verification

Verify Atlas session JWTs **locally** — no round trip per request. The JWKS is cached in-process with kid-miss refetch throttled to once per minute (§7.3).

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

## Resources

All 45 namespaces are available on the client: `users`, `sessions`, `organizations`, `roles`, `permissions`, `oauth_clients`, `resource_servers`, `sso_connections`, `scim_tokens`, `scim_provisioning`, `domains`, `waitlist`, `allowlist`, `blocklist`, `attack_protection`, `actor_tokens`, `invitations`, `webhooks`, `sign_in_tokens`, `audit_logs`, `jwt_templates`, `api_keys`, `oauth_providers`, `sso_onboarding`, `fga`, `rate_limit_policy`, `risk_based_mfa`, `bot_signals`, `network_acls`, `managed_waf`, `log_streams`, `branding`, `email_templates`, `sms_templates`, `localizations`, `actions`, `billing`, `messaging`, `import_export`, `data_subject_requests`, `radius_clients`, `lti_platforms`, `instance`, `instance_security`, `tokens`.

## Development

```sh
bundle install
rake test        # or: ruby -Ilib -Itest test/client_test.rb
```

## License

MIT
