# frozen_string_literal: true

module Atlas
  # Per-template mint settings for JWT templates, checked before the request is sent.
  #
  #   atlas.jwt_templates.create({ name: "hasura", claims: { "x-role" => "{{org.role}}" },
  #                                settings: Atlas::JwtTemplateSettings.build(lifetime_seconds: 300, audience: "hasura") })
  module JwtTemplateSettings
    ALGORITHMS = %w[RS256 HS256].freeze

    module_function

    # @param lifetime_seconds [Integer, nil] 10-86400 (nil clears it on update; omit to leave it).
    # @param audience [String, nil]
    # @param algorithm [String] +RS256+ (default) or +HS256+.
    # @param signing_secret [String] the HS256 shared secret, 16+ characters; write-only.
    # @return [Hash] the +settings+ body (only the fields you passed).
    def build(lifetime_seconds: Generated::UNSET, audience: Generated::UNSET, algorithm: Generated::UNSET, signing_secret: Generated::UNSET)
      out = {}
      unless lifetime_seconds.equal?(Generated::UNSET)
        unless lifetime_seconds.nil? || (lifetime_seconds.is_a?(Integer) && lifetime_seconds.between?(10, 86_400))
          raise ArgumentError, "lifetime_seconds must be 10-86400 (or nil to clear it)."
        end
        out[:lifetime_seconds] = lifetime_seconds
      end
      out[:audience] = audience unless audience.equal?(Generated::UNSET)
      unless algorithm.equal?(Generated::UNSET)
        raise ArgumentError, "algorithm must be one of #{ALGORITHMS.join(', ')}." unless ALGORITHMS.include?(algorithm)
        out[:algorithm] = algorithm
      end
      unless signing_secret.equal?(Generated::UNSET)
        raise ArgumentError, "signing_secret must be at least 16 characters." unless signing_secret.is_a?(String) && signing_secret.length >= 16
        out[:signing_secret] = signing_secret
      end
      out
    end
  end
end
