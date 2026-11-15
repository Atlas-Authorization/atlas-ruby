# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "openssl"
require "securerandom"
require "uri"

require_relative "error"
require_relative "transport"

module Atlas
  # Ed25519 raw-key helpers: +OpenSSL::PKey#raw_public_key+ / +new_raw_private_key+ need the openssl gem 3.3 (Ruby 3.4), so go via DER.
  module Ed25519Raw
    PKCS8_PREFIX = ["302e020100300506032b657004220420"].pack("H*")

    def self.public_bytes(key) = key.public_to_der.byteslice(-32, 32)

    def self.from_seed(seed) = OpenSSL::PKey.read(PKCS8_PREFIX + seed)
  end
end

module Atlas
  # Atlas refused a machine request. +code+ is the machine-readable error code when the answer had one.
  class MachineClientError < Error
    attr_reader :status, :code

    def initialize(status, code, message)
      super(message)
      @status = status
      @code = code
    end
  end

  # What a machine keeps between runs. The private key never leaves it.
  MachineIdentity = Struct.new(:issuer, :machine_id, :private_key_pem, :public_key_pem, :enrolled_at, keyword_init: true) do
    def to_h = { "issuer" => issuer, "machine_id" => machine_id, "private_key_pem" => private_key_pem,
                 "public_key_pem" => public_key_pem, "enrolled_at" => enrolled_at }

    def self.from_h(h) = new(issuer: h["issuer"], machine_id: h["machine_id"], private_key_pem: h["private_key_pem"],
                             public_key_pem: h["public_key_pem"], enrolled_at: h["enrolled_at"])
  end

  # A machine token. +token_type+ is +"DPoP"+ when bound to this client's key: send +Authorization: DPoP <token>+
  # with a {MachineClient#dpop_proof}. +expires_at+ is epoch ms; +constraints+ are the grant's constraints.
  MachineToken = Struct.new(:token, :token_type, :expires_at, :audience, :scope, :constraints, :organization_id, keyword_init: true)

  # The outcome of enrolment. +approval_required+ is true when an administrator must approve the machine first.
  MachineEnrolResult = Struct.new(:machine_id, :status, :approval_required, keyword_init: true)

  # Keeps the identity in memory (tests, short-lived jobs that enrol every run).
  class MemoryMachineStore
    def initialize(initial = nil)
      @identity = initial
    end

    def load = @identity
    def save(identity) = (@identity = identity)
    def clear = (@identity = nil)
  end

  # Keeps the identity in one file, written 0600 in a 0700 directory (atomically, so a crash never leaves half a key).
  class FileMachineStore
    def initialize(path)
      @path = path
    end

    def load
      MachineIdentity.from_h(JSON.parse(File.read(@path)))
    rescue Errno::ENOENT, JSON::ParserError
      nil
    end

    def save(identity)
      dir = File.dirname(@path)
      FileUtils.mkdir_p(dir, mode: 0o700)
      File.chmod(0o700, dir)
      tmp = "#{@path}.#{Process.pid}.tmp"
      File.write(tmp, JSON.generate(identity.to_h), perm: 0o600)
      File.rename(tmp, @path)
    end

    def clear
      FileUtils.rm_f(@path)
    end
  end

  # Ed25519 key generation for machine keys.
  module MachineSigning
    module_function

    # Machine keys are the one feature that needs the openssl gem 3.0 (Ruby 3.1+); everything else runs on Ruby 3.0.
    def require_openssl_3!
      return if Gem::Version.new(OpenSSL::VERSION) >= Gem::Version.new("3.0.0")

      raise Atlas::ConfigurationError, "Machine keys need the openssl gem 3.0 or newer (Ruby 3.1+); this process has openssl #{OpenSSL::VERSION}. " \
                                       "Add `gem \"openssl\", \">= 3.0\"` to your Gemfile."
    end

    def ed25519_pair
      require_openssl_3!

      key = OpenSSL::PKey.generate_key("ED25519")
      { private_pem: key.private_to_pem, public_pem: key.public_to_pem }
    end
  end

  # DPoP (RFC 9449) proof signing for a machine's key: Ed25519 or P-256, as PKCS#8 PEM.
  module MachineDpop
    module_function

    # A new Ed25519 key, as a PKCS#8 PEM.
    def generate_key = MachineSigning.ed25519_pair[:private_pem]

    # @return [Hash] +{ jwk:, alg: }+: the public JWK and the JWS algorithm (+"EdDSA"+ or +"ES256"+).
    def public_jwk_of(private_key_pem)
      key = OpenSSL::PKey.read(private_key_pem)
      if key.respond_to?(:oid) && key.oid == "ED25519"
        { jwk: { "kty" => "OKP", "crv" => "Ed25519", "x" => b64u(Atlas::Ed25519Raw.public_bytes(key)) }, alg: "EdDSA" }
      elsif key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == "prime256v1"
        point = key.public_key.to_bn(:uncompressed).to_s(2)
        { jwk: { "kty" => "EC", "crv" => "P-256", "x" => b64u(point.byteslice(1, 32)), "y" => b64u(point.byteslice(33, 32)) }, alg: "ES256" }
      else
        raise ArgumentError, "A DPoP key must be Ed25519 or P-256."
      end
    end

    # The JWK thumbprint (+cnf.jkt+) tokens bound to this key carry.
    def thumbprint(private_key_pem)
      jwk = public_jwk_of(private_key_pem)[:jwk]
      canonical = if jwk["kty"] == "EC"
                    %({"crv":"#{jwk['crv']}","kty":"#{jwk['kty']}","x":"#{jwk['x']}","y":"#{jwk['y']}"})
                  else
                    %({"crv":"#{jwk['crv']}","kty":"#{jwk['kty']}","x":"#{jwk['x']}"})
                  end
      b64u(Digest::SHA256.digest(canonical))
    end

    # A DPoP proof JWT for one call: +htm+ / +htu+ (origin and path, no query), optional +ath+ (the access token's
    # hash) and +nonce+ (when the API answered +use_dpop_nonce+). +now+ returns epoch milliseconds.
    def create_proof(private_key_pem:, method:, url:, access_token: nil, nonce: nil, now: nil)
      info = public_jwk_of(private_key_pem)
      uri = URI.parse(url)
      origin = "#{uri.scheme}://#{uri.host}#{uri.port == uri.default_port ? '' : ":#{uri.port}"}"
      payload = { "jti" => SecureRandom.uuid, "htm" => method.to_s.upcase, "htu" => "#{origin}#{uri.path}",
                  "iat" => (now ? now.call / 1000 : Time.now.to_i) }
      payload["ath"] = b64u(Digest::SHA256.digest(access_token)) if access_token
      payload["nonce"] = nonce if nonce
      header = { "typ" => "dpop+jwt", "alg" => info[:alg], "jwk" => info[:jwk] }
      input = "#{b64u(JSON.generate(header))}.#{b64u(JSON.generate(payload))}"
      key = OpenSSL::PKey.read(private_key_pem)
      signature = if info[:alg] == "EdDSA"
                    key.sign(nil, input)
                  else
                    # ES256 wants the raw r||s pair, not the DER the library returns.
                    OpenSSL::ASN1.decode(key.sign("SHA256", input)).value.map { |i| i.value.to_s(2).rjust(32, "\0") }.join
                  end
      "#{input}.#{b64u(signature)}"
    end

    def b64u(bytes) = Base64.urlsafe_encode64(bytes, padding: false)
  end

  # The device side of machine enrolment, for a service or device of your own: generate an Ed25519 key, enrol
  # with a token or a short code, then trade a signed challenge for short-lived machine tokens, cached until
  # shortly before they expire. The private key never leaves the {MachineIdentity} store.
  #
  #   machine = Atlas::MachineClient.new(issuer: "https://auth.example.com", store: Atlas::FileMachineStore.new("/var/lib/app/machine.json"))
  #   machine.enroll(credential: "met_...", name: "billing-worker") unless machine.enrolled?
  #   token = machine.get_token(audience: "https://api.example.com", scopes: ["invoices:read"])
  #   http.get(url, "Authorization" => "Bearer #{token.token}")
  class MachineClient
    # @param issuer [String] your instance's issuer URL: the +iss+ of its tokens.
    # @param store [#load, #save, #clear] see {FileMachineStore} / {MemoryMachineStore}.
    # @param http [#call, nil] injectable requester (the Transport +http:+ seam).
    # @param refresh_skew_seconds [Integer] fetch a new token this long before the cached one expires.
    # @param dpop_key [String, true, nil] bind every token to a DPoP key (PKCS#8 PEM, Ed25519 or P-256), or +true+ for
    #   a key made in memory for this client. Needed when the machine's token binding is +dpop+.
    # @param now [#call, nil] clock returning epoch milliseconds.
    def initialize(issuer:, store:, http: nil, refresh_skew_seconds: 60, dpop_key: nil, now: nil)
      MachineSigning.require_openssl_3!
      @issuer = issuer.to_s.sub(%r{/+\z}, "")
      @store = store
      @http = http || NetHTTPRequester.new
      @skew_ms = refresh_skew_seconds * 1000
      @dpop_key = dpop_key == true ? MachineDpop.generate_key : dpop_key
      @now = now
      @cache = {}
      @mutex = Mutex.new
    end

    # Sign +nonce+ with an Ed25519 private key: pure Ed25519 over the nonce's UTF-8 bytes, base64url.
    def self.sign_challenge(private_key_pem, nonce)
      Base64.urlsafe_encode64(OpenSSL::PKey.read(private_key_pem).sign(nil, nonce.to_s.b), padding: false)
    end

    # The public key (SPKI PEM) re-derived from a private key: check a store was not swapped.
    def self.public_key_pem_of(private_key_pem) = OpenSSL::PKey.read(private_key_pem).public_to_pem

    # Generate a key, enrol with a +met_+ token or a short code (+XXXX-XXXX+), and store the identity. Only the
    # public half of the key is sent.
    # @return [Atlas::MachineEnrolResult]
    def enroll(credential:, name:, metadata: nil, device_key: nil)
      pair = MachineSigning.ed25519_pair
      body = { enrolment_token: credential.to_s.strip, name: name, public_key_pem: pair[:public_pem] }
      body[:metadata] = metadata if metadata
      body[:device_key] = device_key if device_key
      res = post("/v1/machines/enroll", body)
      @store.save(MachineIdentity.new(issuer: @issuer, machine_id: res["id"], private_key_pem: pair[:private_pem],
                                      public_key_pem: pair[:public_pem], enrolled_at: res["enrolled_at"] || now))
      @mutex.synchronize { @cache.clear }
      MachineEnrolResult.new(machine_id: res["id"], status: res["status"], approval_required: res["approval_required"] == true)
    end

    def enrolled? = !identity.nil?
    def machine_id = identity&.machine_id

    # A machine token, from the cache while it has more than the refresh skew left. Concurrent callers asking for the
    # same thing share one mint.
    # @return [Atlas::MachineToken]
    def get_token(audience: nil, scopes: nil, scope_presets: nil, organization_id: nil)
      key = JSON.generate([audience.to_s, Array(scopes).sort, Array(scope_presets).sort, organization_id.to_s])
      @mutex.synchronize do
        hit = @cache[key]
        return hit if hit && hit.expires_at - @skew_ms > now

        @cache[key] = mint(audience, scopes, scope_presets, organization_id)
      end
    end

    # A DPoP proof for one call to your API with a token this client minted. Needs the +dpop_key+ option.
    def dpop_proof(token:, method:, url:, nonce: nil)
      raise MachineClientError.new(0, "dpop_not_configured", "Create the client with the `dpop_key` option to sign DPoP proofs.") unless @dpop_key

      MachineDpop.create_proof(private_key_pem: @dpop_key, method: method, url: url, access_token: token, nonce: nonce, now: @now)
    end

    # The thumbprint (+cnf.jkt+) tokens minted by this client carry, or nil without a +dpop_key+.
    def dpop_thumbprint = @dpop_key && MachineDpop.thumbprint(@dpop_key)

    # Forget cached tokens (the stored identity stays).
    def clear_tokens = @mutex.synchronize { @cache.clear }

    # Forget the identity too: the machine must enrol again.
    def reset
      clear_tokens
      @store.clear
    end

    private

    def now = (@now ? @now.call : (Time.now.to_f * 1000)).to_i

    # The stored identity, or nil before enrolment (or when it belongs to another issuer).
    def identity
      i = @store.load
      i && i.issuer == @issuer ? i : nil
    end

    def mint(audience, scopes, scope_presets, organization_id)
      id = identity or raise MachineClientError.new(0, "not_enrolled", "This machine is not enrolled. Call enroll first.")
      challenge = post("/v1/machines/challenge", { machine_id: id.machine_id })
      body = { machine_id: id.machine_id, nonce: challenge["nonce"], signature: self.class.sign_challenge(id.private_key_pem, challenge["nonce"]) }
      body[:audience] = audience if audience
      body[:scopes] = scopes if scopes
      body[:scope_presets] = scope_presets if scope_presets
      body[:organization_id] = organization_id if organization_id
      res = post("/v1/machines/token", body, proof: true)
      MachineToken.new(token: res["token"], token_type: res["token_type"] == "DPoP" ? "DPoP" : "Bearer",
                       expires_at: now + (res["expires_in"].to_i * 1000), audience: res["audience"], scope: res["scope"],
                       constraints: res["constraints"], organization_id: res["organization_id"])
    end

    def post(path, body, proof: false)
      url = "#{@issuer}#{path}"
      headers = { "content-type" => "application/json", "accept" => "application/json" }
      headers["dpop"] = MachineDpop.create_proof(private_key_pem: @dpop_key, method: "POST", url: url, now: @now) if proof && @dpop_key
      status, text, = @http.call("POST", url, headers, JSON.generate(body))
      json = begin
        text.to_s.empty? ? {} : JSON.parse(text)
      rescue JSON::ParserError
        {}
      end
      json = {} unless json.is_a?(Hash)
      unless status.between?(200, 299)
        first = json["errors"].is_a?(Array) ? json["errors"].first : nil
        raise MachineClientError.new(status, (first && first["code"]) || json["code"],
                                     (first && first["message"]) || json["message"] || "Request failed with status #{status}.")
      end
      json
    end
  end
end
