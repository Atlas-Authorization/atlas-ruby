# frozen_string_literal: true

require_relative "test_helper"
require "atlas/rails"
require "rack/mock"
require "jwt"
require "openssl"

# The Rails-native layer over §7.3 verification. Mints real RS256 session tokens
# with a test key, serves the matching JWKS through the JwksCache +fetch_impl:+
# seam (no network), and drives the Rack middleware and the controller concern
# the way Rails would. The middleware and helpers wrap the gem's existing
# {Atlas::Backend}; these tests assert the wiring, not the crypto.
class RailsIntegrationTest < Minitest::Test
  ISSUER = "https://acme.atlas.dev"

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @jwk = JWT::JWK.new(@rsa)
    jwks_json = JSON.generate({ "keys" => [@jwk.export] })
    fetch = ->(_url) { [200, jwks_json] }
    @backend = Atlas::Backend.new(
      jwks_url: "https://acme.atlas.dev/v1/jwks",
      issuer: ISSUER,
      fetch_impl: fetch,
    )
  end

  def teardown
    Atlas.reset_configuration!
  end

  def sign(claims = {})
    now = Time.now.to_i
    payload = { "iss" => ISSUER, "sub" => "user_1", "iat" => now, "nbf" => now, "exp" => now + 3600 }.merge(claims)
    JWT.encode(payload, @rsa, "RS256", { kid: @jwk.kid })
  end

  # Run one request through the middleware and return the terminating app's env.
  def run_middleware(middleware_opts = {}, **env_overrides)
    captured = nil
    app = lambda do |env|
      captured = env
      [200, { "content-type" => "text/plain" }, ["ok"]]
    end
    middleware = Atlas::Rails::Middleware.new(app, backend: @backend, **middleware_opts)
    response = Rack::MockRequest.new(middleware).get("/", env_overrides)
    [response.status, captured]
  end

  # --- Middleware -----------------------------------------------------------

  def test_middleware_populates_env_from_a_bearer_header
    status, env = run_middleware({}, "HTTP_AUTHORIZATION" => "Bearer #{sign('sid' => 'sess_1')}")
    assert_equal 200, status
    result = env[Atlas::Rails::Middleware::ENV_KEY]
    assert result.ok?, "expected a verified result, got #{result.reason.inspect}"
    assert_equal "user_1", result.claims["sub"]
    assert_equal "sess_1", result.claims["sid"]
  end

  def test_middleware_populates_env_from_the_session_cookie
    _, env = run_middleware({}, "HTTP_COOKIE" => "__session=#{sign}")
    assert env[Atlas::Rails::Middleware::ENV_KEY].ok?
  end

  def test_middleware_passes_through_unauthenticated_when_no_token
    status, env = run_middleware
    assert_equal 200, status, "an unauthenticated request must still reach the app"
    result = env[Atlas::Rails::Middleware::ENV_KEY]
    refute result.ok?
    assert_equal :malformed, result.reason
  end

  def test_middleware_passes_through_on_an_invalid_token
    status, env = run_middleware({}, "HTTP_AUTHORIZATION" => "Bearer not.a.jwt")
    assert_equal 200, status
    refute env[Atlas::Rails::Middleware::ENV_KEY].ok?
  end

  def test_middleware_degrades_to_unauthenticated_when_unconfigured
    unconfigured = Atlas::Configuration.new
    unconfigured.jwks_url = nil
    unconfigured.issuer = nil

    captured = nil
    app = ->(env) { captured = env; [200, {}, ["ok"]] }
    middleware = Atlas::Rails::Middleware.new(app, configuration: unconfigured)
    response = Rack::MockRequest.new(middleware).get("/", "HTTP_AUTHORIZATION" => "Bearer #{sign}")

    assert_equal 200, response.status
    refute captured[Atlas::Rails::Middleware::ENV_KEY].ok?
  end

  # --- Controller concern ---------------------------------------------------

  # A minimal stand-in for an ActionController::Base subclass: it includes the
  # real concern and provides just the +request+ and +render+ surface the
  # helpers touch, so the concern's own logic is what's under test.
  class StubController
    include Atlas::Rails::Controller

    Req = Struct.new(:env)

    attr_reader :rendered

    def initialize(env)
      @request = Req.new(env)
      @rendered = nil
    end

    attr_reader :request

    def render(**opts)
      @rendered = opts
    end
  end

  def controller_for(result)
    StubController.new(Atlas::Rails::Middleware::ENV_KEY => result)
  end

  def test_require_atlas_auth_allows_a_valid_session
    controller = controller_for(@backend.verify(sign))
    assert controller.require_atlas_auth!
    assert_nil controller.rendered
    assert controller.atlas_authenticated?
    assert_equal "user_1", controller.current_atlas_user_id
  end

  def test_require_atlas_auth_401s_without_a_session
    controller = controller_for(Atlas::VerifyResult.failure(:malformed))
    refute controller.require_atlas_auth!
    assert_equal :unauthorized, controller.rendered[:status]
    assert_equal "UNAUTHENTICATED", controller.rendered[:json][:errors].first["code"]
    refute controller.atlas_authenticated?
    assert_nil controller.current_atlas_user_id
  end

  def test_current_atlas_session_defaults_to_a_failure_without_middleware
    controller = StubController.new({})
    refute controller.atlas_authenticated?
    assert_nil controller.current_atlas_user_id
  end

  def test_atlas_authorize_allows_a_permitted_session
    result = @backend.verify(sign("org_permissions" => ["org:billing:manage"]))
    controller = controller_for(result)
    assert controller.atlas_authorize!(permission: "org:billing:manage")
    assert_nil controller.rendered
  end

  def test_atlas_authorize_403s_a_session_missing_the_permission
    result = @backend.verify(sign("org_permissions" => ["org:billing:read"]))
    controller = controller_for(result)
    refute controller.atlas_authorize!(permission: "org:billing:manage")
    assert_equal :forbidden, controller.rendered[:status]
    assert_equal "FORBIDDEN", controller.rendered[:json][:errors].first["code"]
  end

  def test_atlas_authorize_401s_an_unauthenticated_session
    controller = controller_for(Atlas::VerifyResult.failure(:invalid))
    refute controller.atlas_authorize!(permission: "org:billing:manage")
    assert_equal :unauthorized, controller.rendered[:status]
  end

  # --- Configuration --------------------------------------------------------

  def test_configure_sets_and_builds_a_backend
    Atlas.configure do |c|
      c.jwks_url = "https://acme.atlas.dev/v1/jwks"
      c.issuer = ISSUER
    end
    assert Atlas.configuration.configured?
    assert_instance_of Atlas::Backend, Atlas.configuration.backend
  end

  def test_unconfigured_backend_raises_rather_than_failing_silently
    config = Atlas::Configuration.new
    config.jwks_url = nil
    config.issuer = nil
    assert_raises(Atlas::ConfigurationError) { config.backend }
  end
end
