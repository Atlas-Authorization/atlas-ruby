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

    # A short human summary for logs. Never includes the secret key.
    def to_s
      "#{self.class.name}: status=#{@status} code=#{code.inspect} #{super}"
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
