# frozen_string_literal: true

module Atlas
  # Base class for every error the SDK raises. Rescue +Atlas::Error+ to catch
  # anything the gem can throw.
  class Error < StandardError; end

  # Raised before a request goes out when the client is misconfigured
  # (e.g. a missing secret key).
  class ConfigurationError < Error; end

  # Raised on any non-2xx response from the Backend API.
  #
  # Atlas answers a failed BAPI call with the §9.1 envelope:
  #
  #   { "errors": [ { "code", "message", "param?", "meta?" } ] }
  #
  # +code+ is the stable, machine-readable part of that contract — integrators
  # branch on it (+LAST_ADMIN+, +NOT_FOUND+, +SCOPE_MISSING+, ...) — so it is
  # surfaced first-class here rather than buried in a parsed body. The raw
  # +errors+ array and the HTTP +status+ are both kept so a caller can inspect
  # +param+/+meta+ (e.g. a rate limit's +retry_after+) when they need to.
  class APIError < Error
    # @return [Integer] HTTP status of the failed response.
    attr_reader :status

    # @return [Array<Hash>] the full §9.1 error envelope, in order. Each item
    #   carries string keys "code", "message", and optionally "param"/"meta".
    attr_reader :errors

    def initialize(status, errors, message = nil)
      @status = status
      @errors = errors || []
      first = @errors.first
      super(message || (first && (first["message"] || first[:message])) ||
        "Atlas API request failed with status #{status}")
    end

    # The first error's stable code — the field callers branch on most.
    # @return [String, nil]
    def code
      first = @errors.first
      first && (first["code"] || first[:code])
    end

    # True when any error in the envelope carries the given stable code.
    def has_code?(code)
      @errors.any? { |e| (e["code"] || e[:code]) == code }
    end

    # Both the current and the legacy code for a missing scope.
    SCOPE_CODES = %w[INSUFFICIENT_SCOPE SCOPE_MISSING].freeze

    # True for +INSUFFICIENT_SCOPE+ and its legacy alias +SCOPE_MISSING+.
    def insufficient_scope?
      SCOPE_CODES.any? { |c| has_code?(c) }
    end

    # The scope a +INSUFFICIENT_SCOPE+ error says is missing (+meta.required_scope+).
    def required_scope
      meta = error_field("meta")
      meta.is_a?(Hash) ? (meta["required_scope"] || meta[:required_scope]) : nil
    end

    # True when a browser-origin-locked key was used from another origin (+ORIGIN_NOT_ALLOWED+).
    def origin_not_allowed?
      has_code?(ErrorCode::ORIGIN_NOT_ALLOWED)
    end

    # True when the action needs a step-up (+STEP_UP_REQUIRED+).
    def step_up_required?
      has_code?(ErrorCode::STEP_UP_REQUIRED)
    end

    # Route suggestions on a +ROUTE_NOT_FOUND+ error.
    def did_you_mean
      Array(error_field("did_you_mean"))
    end

    # The methods a +ROUTE_NOT_FOUND+ path does accept.
    def allowed_methods
      Array(error_field("allowed_methods"))
    end

    # Link to the error's page (+https://atlasauth.net/errors/<code>+).
    def docs_url
      error_field("docs_url")
    end

    # A short human summary for logs. Never includes the secret key.
    def to_s
      "#{self.class.name}: status=#{@status} code=#{code.inspect} #{super}"
    end

    private

    def error_field(name)
      first = @errors.first
      first && (first[name] || first[name.to_sym])
    end
  end

  # 400 — the request was malformed or a parameter was invalid.
  class BadRequestError < APIError; end
  # 401 — the secret key is missing, wrong, or revoked.
  class AuthenticationError < APIError; end
  # 403 — authenticated but not permitted (e.g. scope missing).
  class PermissionError < APIError; end
  # 404 — the resource does not exist for this instance.
  class NotFoundError < APIError; end
  # 409 — a conflict/terminal-state error (e.g. re-actioning a DSAR).
  class ConflictError < APIError; end
  # 422 — the request was well-formed but semantically rejected.
  class UnprocessableEntityError < APIError; end
  # 429 — rate limited. Inspect +errors.first["meta"]["retry_after"]+.
  class RateLimitError < APIError; end
  # 5xx — an Atlas-side failure.
  class ServerError < APIError; end

  # Stable error codes worth branching on, for +APIError#code+ / +#has_code?+:
  #
  #   rescue Atlas::UnprocessableEntityError => e
  #     raise unless e.has_code?(Atlas::ErrorCode::UNKNOWN_FIELD)
  module ErrorCode
    # A request field the endpoint does not accept (strict bodies). +param+ names it.
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    # The body set a field that is not writable on this endpoint (+param+ names
    # it; the message names the call that changes it).
    READ_ONLY_FIELD = "READ_ONLY_FIELD"
    # A flow would send an email but the instance has no way to deliver it.
    EMAIL_DELIVERY_NOT_CONFIGURED = "EMAIL_DELIVERY_NOT_CONFIGURED"
    # An email-based sign-in method cannot be turned on without an email provider.
    EMAIL_PROVIDER_REQUIRED = "EMAIL_PROVIDER_REQUIRED"
    # The email provider cannot be removed while email-dependent features are on
    # (+meta["features"]+ lists them); +messaging.delete_channel("email", force: true)+ removes it anyway.
    EMAIL_PROVIDER_IN_USE = "EMAIL_PROVIDER_IN_USE"
    # Captcha is bring-your-own-keys: turning it on (or switching provider) needs that
    # provider's site key and secret stored first.
    CAPTCHA_KEYS_REQUIRED = "CAPTCHA_KEYS_REQUIRED"
    # A captcha key a live flow uses cannot be removed (+meta["flows"]+);
    # +instance_security.delete_captcha_secret(force: true)+ removes it anyway.
    CAPTCHA_IN_USE = "CAPTCHA_IN_USE"
    # The development email sender is not available on a production instance (409).
    DEVELOPMENT_EMAIL_NOT_ALLOWED = "DEVELOPMENT_EMAIL_NOT_ALLOWED"
    # The development email sender is not available on this deployment (503).
    DEVELOPMENT_EMAIL_UNAVAILABLE = "DEVELOPMENT_EMAIL_UNAVAILABLE"
    # The development sender's daily or per-recipient hourly cap is spent (429;
    # +meta["window"]+, +meta["retry_after_seconds"]+).
    DEVELOPMENT_EMAIL_LIMIT_REACHED = "DEVELOPMENT_EMAIL_LIMIT_REACHED"
    # The development sender sends only Atlas's own sign-in emails (422).
    DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED = "DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED"
    # Referrals cannot be enabled until the provider's needs are set (422; +meta+ names what is missing).
    REFERRALS_NOT_CONFIGURED = "REFERRALS_NOT_CONFIGURED"
    # Another user on the instance already holds that referral code (409).
    REFERRAL_CODE_TAKEN = "REFERRAL_CODE_TAKEN"
    # Managed WAF provision or deprovision on an instance with no WAF configuration saved (422; +meta.action+).
    MANAGED_WAF_NOT_CONFIGURED = "MANAGED_WAF_NOT_CONFIGURED"
    # A billing plan that subscriptions still use cannot be deleted.
    PLAN_IN_USE = "PLAN_IN_USE"
    # The key is valid but for a different API surface (e.g. a platform key on an instance route).
    WRONG_KEY_SURFACE = "WRONG_KEY_SURFACE"
    # The key is missing, malformed, revoked or unknown.
    INVALID_KEY = "INVALID_KEY"
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    # Legacy name of {INSUFFICIENT_SCOPE}; older servers still send it, and the new
    # code carries it in +meta["legacy_code"]+. Branch on {Atlas::APIError#insufficient_scope?}.
    SCOPE_MISSING = "SCOPE_MISSING"
    # The key lacks a scope the route needs (+meta["required_scope"]+ names it).
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    # A key locked to +allowed_origins+ was used from another browser origin (403).
    ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
    # The action needs a fresh second factor (step-up); re-authenticate and retry.
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    # No such route (was NOT_FOUND). The item carries +did_you_mean+, +allowed_methods+ and +docs_url+.
    ROUTE_NOT_FOUND = "ROUTE_NOT_FOUND"
    # The partner link the call needs is not set up (or not usable).
    PARTNER_LINK_UNAVAILABLE = "PARTNER_LINK_UNAVAILABLE"
    # The route only exists on a live instance.
    NOT_A_LIVE_INSTANCE = "NOT_A_LIVE_INSTANCE"
    # The route only exists on a test-mode instance.
    TEST_MODE_ONLY = "TEST_MODE_ONLY"
    # Test helpers are not available on this deployment.
    TESTING_UNAVAILABLE = "TESTING_UNAVAILABLE"
    # An idempotency key was reused with a different request (e.g. another unit or amount).
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    # A usage debit would exceed one of the API key's spend caps (the +code+ of a refused debit).
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    # The session was revoked, timed out from inactivity, or passed its absolute expiry.
    SESSION_REVOKED = "SESSION_REVOKED"
    SESSION_IDLE_EXPIRED = "SESSION_IDLE_EXPIRED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
  end

  module ErrorFactory
    # Map an HTTP status onto the most specific error class.
    STATUS_MAP = {
      400 => BadRequestError,
      401 => AuthenticationError,
      403 => PermissionError,
      404 => NotFoundError,
      409 => ConflictError,
      422 => UnprocessableEntityError,
      429 => RateLimitError
    }.freeze

    # Build the right typed error from a status + parsed error items.
    def self.build(status, errors)
      klass = STATUS_MAP[status] || (status >= 500 ? ServerError : APIError)
      klass.new(status, errors)
    end
  end
end
