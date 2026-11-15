# frozen_string_literal: true

require_relative "test_helper"
require "jwt"
require "openssl"
require "uri"
require "base64"
require "rack"

class RelyingPartyTest < Minitest::Test
  ISSUER = "https://auth.example.com"
  CLIENT = "app_1"
  REDIRECT = "https://app.example.com/auth/callback"
  SECRET = "s" * 40

  # A fake issuer: discovery, JWKS and a token endpoint that mints the ID token for the nonce it was given.
  class Issuer
    attr_reader :calls
    attr_accessor :nonce, :claims_override, :token_status, :sessions_status

    def initialize
      @key = OpenSSL::PKey::RSA.generate(2048)
      @jwk = JWT::JWK.new(@key, kid: "k1").export
      @calls = []
      @token_status = 200
      @sessions_status = 200
      @claims_override = {}
    end

    def mint(claims = {})
      now = Time.now.to_i
      payload = { "iss" => ISSUER, "aud" => CLIENT, "sub" => "user_1", "sid" => "ses_1", "iat" => now, "exp" => now + 300,
                  "nonce" => nonce, "auth_time" => now, "email" => "ada@example.com", "email_verified" => true,
                  "name" => "Ada", "org_id" => "org_1", "org_role" => "admin" }.merge(claims)
      JWT.encode(payload, @key, "RS256", { "kid" => "k1" })
    end

    def call(method, url, headers, body)
      @calls << { method: method, url: url, headers: headers, body: body }
      path = URI.parse(url).path
      case [method, path]
      when ["GET", "/.well-known/openid-configuration"]
        json(200, "issuer" => ISSUER, "authorization_endpoint" => "#{ISSUER}/oauth2/authorize",
                  "token_endpoint" => "#{ISSUER}/oauth2/token", "jwks_uri" => "#{ISSUER}/jwks",
                  "end_session_endpoint" => "#{ISSUER}/oauth2/logout")
      when ["GET", "/jwks"] then json(200, "keys" => [@jwk])
      when ["POST", "/oauth2/token"]
        return json(@token_status, "error" => "invalid_grant", "error_description" => "bad code") unless @token_status == 200

        json(200, "id_token" => mint(@claims_override), "access_token" => "at_1", "expires_in" => 3600, "token_type" => "Bearer")
      when ["POST", "/oauth2/session/touch"]
        @sessions_status == 200 ? json(200, "idle_expires_at" => 1_900_000_000_000) : json(404, "error" => "session_not_found")
      when ["POST", "/v1/sessions/ses_1/touch"] then json(200, "idle_expires_at" => "2030-01-01T00:00:00Z")
      when ["POST", "/v1/sessions/ses_1/revoke"] then json(200, {})
      else json(404, {})
      end
    end

    private

    def json(status, body) = [status, JSON.generate(body), {}]
  end

  def setup
    @issuer = Issuer.new
  end

  def rp(**opts)
    Atlas::RelyingParty.new(issuer: ISSUER, client_id: CLIENT, client_secret: "cs", redirect_uri: REDIRECT, secret: SECRET,
                            http: @issuer, **opts)
  end

  def request(url, cookie: nil, method: "GET")
    Atlas::RP::Request.new(method: method, url: url, headers: cookie ? { "cookie" => cookie } : {})
  end

  def cookie_of(response) = response.cookies.first.split(";").first

  def start_and_return(relying_party, code_state: nil)
    started = relying_party.start(request("https://app.example.com/auth/sign-in?return_to=/billing&ref=abc"))
    query = URI.decode_www_form(URI.parse(started.location).query).to_h
    @issuer.nonce = query["nonce"]
    [started, query, code_state || query["state"]]
  end

  def test_start_builds_a_pkce_authorize_url_and_a_sealed_cookie
    started = rp(forward_params: ["ref"]).start(request("https://app.example.com/auth/sign-in?return_to=/billing&ref=abc&evil=1"))
    assert_equal 302, started.status
    query = URI.decode_www_form(URI.parse(started.location).query).to_h
    assert_equal "code", query["response_type"]
    assert_equal "S256", query["code_challenge_method"]
    assert_equal "abc", query["ref"]
    refute query.key?("evil")
    assert_equal "openid profile email", query["scope"]
    assert_match(/\Aatlas_oidc=s1\.[\w-]+\.[\w-]+; Path=\/auth\/callback; Max-Age=600; HttpOnly; SameSite=Lax; Secure\z/, started.cookies.first)
  end

  def test_full_sign_in_round_trip
    relying_party = rp
    started, _query, state = start_and_return(relying_party)
    result = relying_party.callback(request("#{REDIRECT}?code=c1&state=#{state}", cookie: cookie_of(started)))
    assert_equal "user_1", result.user.sub
    assert_equal "ses_1", result.user.sid
    assert_equal "ada@example.com", result.user.email
    assert_equal true, result.user.email_verified
    assert_equal "org_1", result.user.org_id
    assert_equal "/billing", result.response.location
    assert_match(/Max-Age=0/, result.response.cookies.first)
    assert_equal "at_1", result.tokens.access_token
    token_call = @issuer.calls.find { |c| c[:url].end_with?("/oauth2/token") }
    assert_match(/\ABasic /, token_call[:headers]["authorization"])
    assert_includes token_call[:body], "code_verifier="
  end

  def test_state_mismatch_is_refused_and_clears_the_cookie
    relying_party = rp
    started, = start_and_return(relying_party)
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c1&state=wrong", cookie: cookie_of(started))) }
    assert_equal :state_mismatch, error.code
    assert_match(/Max-Age=0/, error.clear_cookie)
  end

  def test_a_forged_flow_cookie_is_refused
    error = assert_raises(Atlas::OIDC::Error) { rp.callback(request("#{REDIRECT}?code=c&state=s", cookie: "atlas_oidc=s1.AAAA.BBBB")) }
    assert_equal :state_mismatch, error.code
  end

  def test_wrong_nonce_audience_and_expired_tokens_are_refused
    relying_party = rp
    started, _q, state = start_and_return(relying_party)
    @issuer.claims_override = { "nonce" => "other" }
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c&state=#{state}", cookie: cookie_of(started))) }
    assert_equal :invalid_token, error.code
    assert_match(/nonce/, error.message)

    started, _q, state = start_and_return(relying_party)
    @issuer.claims_override = { "nonce" => @issuer.nonce, "aud" => "someone_else" }
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c&state=#{state}", cookie: cookie_of(started))) }
    assert_match(/audience/, error.message)

    started, _q, state = start_and_return(relying_party)
    @issuer.claims_override = { "nonce" => @issuer.nonce, "exp" => Time.now.to_i - 3600, "iat" => Time.now.to_i - 7200 }
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c&state=#{state}", cookie: cookie_of(started))) }
    assert_match(/expired/, error.message)
  end

  def test_token_endpoint_failure_is_reported
    relying_party = rp
    started, _q, state = start_and_return(relying_party)
    @issuer.token_status = 400
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c&state=#{state}", cookie: cookie_of(started))) }
    assert_equal :token_exchange_failed, error.code
    assert_equal "invalid_grant", error.oauth_error
  end

  def test_authorization_error_in_the_callback
    relying_party = rp
    started, _q, state = start_and_return(relying_party)
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?error=access_denied&state=#{state}", cookie: cookie_of(started))) }
    assert_equal :access_denied, error.code
  end

  def test_require_recent_auth
    relying_party = rp
    req = request("https://app.example.com/billing?x=1")
    assert_nil relying_party.require_recent_auth(req, 300, sub: "user_1", auth_time: Time.now.to_i - 10)
    response = relying_party.require_recent_auth(req, 300, sub: "user_1", auth_time: Time.now.to_i - 900)
    query = URI.decode_www_form(URI.parse(response.location).query).to_h
    assert_equal "300", query["max_age"]
    @issuer.nonce = query["nonce"]
    state = query["state"]
    # another user confirming is refused
    @issuer.claims_override = { "sub" => "user_2" }
    error = assert_raises(Atlas::OIDC::Error) { relying_party.callback(request("#{REDIRECT}?code=c&state=#{state}", cookie: cookie_of(response))) }
    assert_equal :subject_mismatch, error.code
    zero = relying_party.require_recent_auth(req, 0, sub: "user_1", auth_time: Time.now.to_i - 120)
    assert_equal "login", URI.decode_www_form(URI.parse(zero.location).query).to_h["prompt"]
  end

  def test_touch_if_due_with_client_credentials_and_with_a_secret_key
    relying_party = rp
    assert_equal :skipped, relying_party.touch_if_due("ses_1", Time.now.to_i - 5)[:status]
    assert_equal :touched, relying_party.touch_if_due("ses_1", nil)[:status]
    @issuer.sessions_status = 404
    assert_equal({ status: :ended, reason: :not_found }, relying_party.touch_if_due("ses_1", nil))
    keyed = rp(secret_key: "sk_test_x", api_url: "https://api.example.com")
    assert_equal :touched, keyed.touch_if_due("ses_1", nil)[:status]
    assert_equal :revoked, keyed.revoke_session("ses_1")
  end

  def test_sign_out_revokes_then_redirects_to_the_end_session_endpoint
    keyed = rp(secret_key: "sk_test_x", api_url: "https://api.example.com", post_logout_redirect_uri: "https://app.example.com/")
    response = keyed.sign_out(sid: "ses_1", id_token: "idt", set_cookies: ["atlas_session=; Max-Age=0"])
    assert response.location.start_with?("#{ISSUER}/oauth2/logout?")
    assert_includes response.location, "id_token_hint=idt"
    assert_equal ["atlas_session=; Max-Age=0"], response.cookies
    assert(@issuer.calls.any? { |c| c[:url].end_with?("/v1/sessions/ses_1/revoke") })
  end

  def test_rack_middleware_signs_in_keeps_a_session_and_signs_out
    relying_party = rp
    session = Atlas::RP::Session.new(secret: SECRET)
    app = ->(env) { [200, {}, [env[Atlas::RP::Middleware::ENV_KEY]&.fetch("email", nil).to_s]] }
    stack = Atlas::RP::Middleware.new(app, rp: relying_party, session: session)

    status, headers, = stack.call(Rack::MockRequest.env_for("https://app.example.com/auth/sign-in?return_to=/home"))
    assert_equal 302, status
    flow_cookie = Array(headers["set-cookie"]).join("\n").split("\n").first.split(";").first
    query = URI.decode_www_form(URI.parse(headers["location"]).query).to_h
    @issuer.nonce = query["nonce"]

    status, headers, = stack.call(Rack::MockRequest.env_for("https://app.example.com/auth/callback?code=c&state=#{query['state']}",
                                                            "HTTP_COOKIE" => flow_cookie))
    assert_equal 302, status
    assert_equal "/home", headers["location"]
    session_cookie = Array(headers["set-cookie"]).join("\n").split("\n").find { |c| c.start_with?("atlas_session=") }.split(";").first

    _status, _headers, body = stack.call(Rack::MockRequest.env_for("https://app.example.com/home", "HTTP_COOKIE" => session_cookie))
    assert_equal "ada@example.com", body.join

    status, headers, = stack.call(Rack::MockRequest.env_for("https://app.example.com/auth/sign-out", "HTTP_COOKIE" => session_cookie))
    assert_equal 302, status
    assert_includes headers["location"], "/oauth2/logout"
    assert_includes Array(headers["set-cookie"]).join("\n"), "atlas_session=; Path=/; Max-Age=0"

    _status, _headers, body = stack.call(Rack::MockRequest.env_for("https://app.example.com/home", "HTTP_COOKIE" => "atlas_session=garbage"))
    assert_equal "", body.join
  end

  def test_session_cookie_is_sealed_and_expires
    clock = Time.now.to_i
    session = Atlas::RP::Session.new(secret: SECRET, max_age: 60, now: -> { clock })
    cookie = session.build({ "sub" => "u" }).split(";").first
    assert_equal "u", session.read(cookie)["sub"]
    refute_includes cookie, "u\""
    assert_nil Atlas::RP::Session.new(secret: "x" * 40).read(cookie)
    clock += 61
    assert_nil session.read(cookie)
  end

  def test_back_channel_logout_ends_bound_sessions
    ended = []
    store = Atlas::MemorySidStore.new
    relying_party = rp(sid_store: store, routes: { backchannel_logout: "/auth/backchannel" },
                       on_backchannel_logout: ->(ids, _claims) { ended.concat(ids) })
    relying_party.bind_session("ses_1", "app_sess_9", Time.now.to_i + 600)
    token = JWT.encode({ "iss" => ISSUER, "aud" => CLIENT, "iat" => Time.now.to_i, "jti" => "j1", "sub" => "user_1", "sid" => "ses_1",
                         "events" => { Atlas::BackchannelLogout::EVENT => {} } },
                       @issuer.instance_variable_get(:@key), "RS256", { "kid" => "k1", "typ" => "logout+jwt" })
    req = Atlas::RP::Request.new(method: "POST", url: "https://app.example.com/auth/backchannel",
                                 body: URI.encode_www_form("logout_token" => token))
    response = relying_party.backchannel_logout(req)
    assert_equal 200, response.status
    assert_equal ["app_sess_9"], ended
    bad = relying_party.backchannel_logout(Atlas::RP::Request.new(method: "POST", url: "https://app.example.com/auth/backchannel", body: "logout_token=nope"))
    assert_equal 400, bad.status
  end
end
