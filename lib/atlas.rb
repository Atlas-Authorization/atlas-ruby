# frozen_string_literal: true

# atlas-auth — the official Ruby backend SDK for Atlas.
#
# A typed client over the +sk_+ Backend API (BAPI), the Ruby peer of the
# TypeScript +@atlasauth/backend+ and Python +atlas-backend+ SDKs, plus §7.3 local
# session-token verification.
#
#   require "atlas"
#
#   atlas = Atlas::Client.new("sk_live_...")
#   user  = atlas.users.create(email_address: "ada@example.com")
#   Atlas.paginate(atlas.organizations).each { |org| puts org["name"] }
#
#   backend = Atlas::Backend.new(
#     jwks_url: "https://api.atlasauth.net/v1/jwks",
#     issuer:   "https://your-instance.atlasauth.net",
#   )
#   result = backend.verify(session_jwt)
#   result.protect(permission: "org:billing:manage") if result.ok?
module Atlas
end

require_relative "atlas/version"
require_relative "atlas/error"
require_relative "atlas/transport"
require_relative "atlas/pagination"
require_relative "atlas/authorization"
require_relative "atlas/jwks_cache"
require_relative "atlas/verifier"
require_relative "atlas/backchannel_logout"
require_relative "atlas/introspection"
require_relative "atlas/access_token"
require_relative "atlas/botid"
require_relative "atlas/device_authorizations"
require_relative "atlas/constants"
require_relative "atlas/handshake"
require_relative "atlas/webhook"
require_relative "atlas/partner_link_requests"
require_relative "atlas/oidc_claims"
require_relative "atlas/atlas_id_tokens"
require_relative "atlas/dry_run"
require_relative "atlas/trace"
require_relative "atlas/policy_source_protocol"
require_relative "atlas/client"
require_relative "atlas/dpop"
require_relative "atlas/legacy_issuers"
require_relative "atlas/better_auth"

module Atlas
  # Convenience constructor mirroring the TS +createAtlasClient+ factory.
  #
  #   atlas = Atlas.client("sk_live_...")
  def self.client(secret_key, **options)
    Client.new(secret_key, **options)
  end
end
