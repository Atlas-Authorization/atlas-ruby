# frozen_string_literal: true

# atlas-auth — the official Ruby backend SDK for Atlas.
#
# A typed client over the +sk_+ Backend API (BAPI), the Ruby peer of the
# TypeScript +@atlas/backend+ and Python +atlas-backend+ SDKs, plus §7.3 local
# session-token verification.
#
#   require "atlas"
#
#   atlas = Atlas::Client.new("sk_live_...")
#   user  = atlas.users.create(email_address: "ada@example.com")
#   Atlas.paginate(atlas.organizations).each { |org| puts org["name"] }
#
#   backend = Atlas::Backend.new(
#     jwks_url: "https://api.atlas.dev/v1/jwks",
#     issuer:   "https://your-instance.atlas.dev",
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
require_relative "atlas/handshake"
require_relative "atlas/client"

module Atlas
  # Convenience constructor mirroring the TS +createAtlasClient+ factory.
  #
  #   atlas = Atlas.client("sk_live_...")
  def self.client(secret_key, **options)
    Client.new(secret_key, **options)
  end
end
