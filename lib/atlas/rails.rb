# frozen_string_literal: true

require_relative "../atlas"

# atlas-auth — Rails-native integration.
#
# This file is loaded ONLY when you ask for it:
#
#   # Gemfile
#   gem "atlas-auth", require: "atlas/rails"
#
# Requiring the base gem (+require "atlas"+) never pulls Rails in, so the SDK
# stays usable in a plain Ruby or non-Rails service. Loading this file in a
# Rails app registers {Atlas::Rails::Railtie}, which:
#
#   * inserts {Atlas::Rails::Middleware} — it verifies the session JWT carried by
#     the +Authorization: Bearer+ header (or the +__session+ cookie) and stashes
#     the {Atlas::VerifyResult} in +env["atlas.auth"]+, and
#   * mixes {Atlas::Rails::Controller} into every controller, giving you
#     +current_atlas_session+, +current_atlas_user_id+, +atlas_authenticated?+,
#     +require_atlas_auth!+ and +atlas_authorize!+.
#
# All verification is delegated to the gem's existing {Atlas::Backend} — this
# layer adds no crypto of its own. Configure it once:
#
#   Atlas.configure do |c|
#     c.jwks_url = "https://your-instance.atlasauth.net/v1/jwks"
#     c.issuer   = "https://your-instance.atlasauth.net"
#     c.secret_key = Rails.application.credentials.dig(:atlas, :secret_key)
#   end
#
# or leave it unset and let it read +ATLAS_JWKS_URL+ / +ATLAS_ISSUER+ /
# +ATLAS_SECRET_KEY+ from the environment or Rails credentials (+atlas:+).
module Atlas
  # Process-wide configuration for the Rails integration. A single
  # {Atlas::Backend} is built from it, lazily, and reused across requests
  # (its JWKS cache is the whole point of keeping one instance).
  class Configuration
    # @return [String, nil] the instance JWKS URL (+ATLAS_JWKS_URL+).
    attr_accessor :jwks_url
    # @return [String, nil] expected +iss+ (+ATLAS_ISSUER+).
    attr_accessor :issuer
    # @return [String, nil] +sk_+ key, only needed for +verify_online+ (+ATLAS_SECRET_KEY+).
    attr_accessor :secret_key
    # @return [String, nil] BAPI base URL, only needed for +verify_online+.
    attr_accessor :bapi_base_url
    # @return [Array<String>, nil] optional +azp+ allowlist.
    attr_accessor :authorized_parties

    def initialize
      @jwks_url           = resolve("ATLAS_JWKS_URL", :jwks_url)
      @issuer             = resolve("ATLAS_ISSUER", :issuer)
      @secret_key         = resolve("ATLAS_SECRET_KEY", :secret_key)
      @bapi_base_url      = resolve("ATLAS_BAPI_BASE_URL", :bapi_base_url)
      @authorized_parties = nil
      @backend            = nil
    end

    # True once the minimum needed for local verification is present.
    def configured?
      !blank?(jwks_url) && !blank?(issuer)
    end

    # The shared, memoized verifier. Raises {Atlas::ConfigurationError} rather
    # than silently building a backend that can never verify anything.
    # @return [Atlas::Backend]
    def backend
      unless configured?
        raise Atlas::ConfigurationError,
              "Atlas Rails integration needs jwks_url and issuer. Set them via " \
              "Atlas.configure, or ATLAS_JWKS_URL / ATLAS_ISSUER (env or Rails " \
              "credentials under `atlas:`)."
      end

      @backend ||= Atlas::Backend.new(
        jwks_url: jwks_url,
        issuer: issuer,
        authorized_parties: authorized_parties,
        secret_key: secret_key,
        bapi_base_url: bapi_base_url,
      )
    end

    # Drop the memoized backend so the next request rebuilds it. Called after
    # {Atlas.configure} so edited values (and a fresh JWKS cache) take effect.
    def reset_backend!
      @backend = nil
    end

    private

    def blank?(value)
      value.nil? || (value.respond_to?(:empty?) && value.empty?)
    end

    # ENV first, then Rails credentials under the +atlas:+ namespace.
    def resolve(env_key, cred_key)
      value = ENV[env_key]
      return value unless blank?(value)

      rails_credential(cred_key)
    end

    def rails_credential(key)
      return nil unless defined?(::Rails) && ::Rails.respond_to?(:application) && ::Rails.application

      atlas = ::Rails.application.credentials.respond_to?(:atlas) ? ::Rails.application.credentials.atlas : nil
      return nil if atlas.nil?

      atlas.respond_to?(:[]) ? (atlas[key] || atlas[key.to_s]) : nil
    rescue StandardError
      nil
    end
  end

  class << self
    # The current {Atlas::Configuration}, created on first use.
    def configuration
      @configuration ||= Configuration.new
    end

    # Configure the Rails integration.
    #
    #   Atlas.configure do |c|
    #     c.jwks_url = "https://your-instance.atlasauth.net/v1/jwks"
    #     c.issuer   = "https://your-instance.atlasauth.net"
    #   end
    #
    # @yieldparam config [Atlas::Configuration]
    # @return [Atlas::Configuration]
    def configure
      yield(configuration) if block_given?
      configuration.reset_backend!
      configuration
    end

    # Forget all configuration. Primarily for tests.
    def reset_configuration!
      @configuration = nil
    end
  end
end

require_relative "rails/middleware"
require_relative "rails/controller"
require_relative "rails/railtie"
