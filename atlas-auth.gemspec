# frozen_string_literal: true

require_relative "lib/atlas/version"

Gem::Specification.new do |spec|
  spec.name        = "atlas-auth"
  spec.version     = Atlas::VERSION
  spec.authors     = ["Atlas"]
  spec.email       = ["support@atlasauth.net"]

  spec.summary     = "Official Ruby backend SDK for Atlas — the sk_ Backend API plus local session-token verification."
  spec.description = <<~DESC
    A typed Ruby client over the Atlas Backend API (BAPI), the Ruby peer of the
    TypeScript @atlas/backend and Python atlas-backend SDKs. Covers the full
    management surface (users, organizations, roles, SSO, SCIM, FGA, webhooks,
    and more) and ships local RS256 session-token verification with an
    in-process JWKS cache.
  DESC
  spec.homepage    = "https://atlasauth.net"
  spec.license     = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["homepage_uri"]      = spec.homepage
  spec.metadata["source_code_uri"]   = "https://github.com/atlas-auth/atlas-ruby"
  spec.metadata["documentation_uri"] = "https://atlasauth.net/docs/sdks/ruby"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.glob("lib/**/*.rb") + %w[README.md LICENSE]
  spec.require_paths = ["lib"]

  # JWT verification (verifier.rb / jwks_cache.rb). Everything else is stdlib.
  spec.add_dependency "jwt", ">= 2.7"

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
