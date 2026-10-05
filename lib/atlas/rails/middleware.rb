# frozen_string_literal: true

module Atlas
  module Rails
    # Rack middleware that authenticates every request and never blocks one.
    #
    # It reads the session JWT from the +Authorization: Bearer+ header (which
    # wins) or the +__session+ cookie, verifies it through the gem's
    # {Atlas::Backend}, and leaves the {Atlas::VerifyResult} at
    # +env["atlas.auth"]+. Whether the token is present, absent or bad, the
    # request passes through — enforcement is the controller's job
    # ({Atlas::Rails::Controller#require_atlas_auth!}), so a public action and a
    # protected one can share the same stack.
    class Middleware
      # The Rack env key the verified result is stashed under.
      ENV_KEY = "atlas.auth"

      # @param app [#call] the next Rack app.
      # @param backend [Atlas::Backend, nil] an explicit verifier; when nil the
      #   shared {Atlas.configuration} backend is used (and built lazily).
      # @param configuration [Atlas::Configuration, nil] an explicit config.
      def initialize(app, backend: nil, configuration: nil)
        @app = app
        @backend = backend
        @configuration = configuration
      end

      def call(env)
        env[ENV_KEY] = authenticate(env)
        @app.call(env)
      end

      private

      # Always returns a {Atlas::VerifyResult}, never raises. A missing or
      # unconfigured backend degrades to "unauthenticated", never a 500.
      def authenticate(env)
        verifier = backend
        return Atlas::VerifyResult.failure(:invalid) if verifier.nil?

        verifier.authenticate_request(
          "authorization" => env["HTTP_AUTHORIZATION"],
          "cookie" => env["HTTP_COOKIE"],
        )
      rescue StandardError
        Atlas::VerifyResult.failure(:invalid)
      end

      def backend
        @backend ||= (@configuration || Atlas.configuration).backend
      rescue Atlas::ConfigurationError
        nil
      end
    end
  end
end
