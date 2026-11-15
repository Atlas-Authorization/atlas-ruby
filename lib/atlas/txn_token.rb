# frozen_string_literal: true

require "json"
require_relative "jws"
require_relative "jwks_cache"
require_relative "verifier"

module Atlas
  # The outcome of {Atlas.verify_transaction_token}. Never raised: check +ok?+.
  TxnTokenResult = Struct.new(:ok, :claims, :scopes, :error, keyword_init: true) do
    def ok? = ok == true
  end

  module_function

  # Verify a transaction token (an RFC 8693-style, short-lived token a workload passes down a call chain,
  # +typ+ +txntoken+jwt+): signature against the issuer's keys, +iss+, +aud+ (the trust domain), expiry, and the
  # claims a transaction token must carry (+txn+, +sub+, +scope+, +req_wl+, +iat+, +exp+).
  #
  #   result = Atlas.verify_transaction_token(token, issuer: "https://auth.example.com", trust_domain: "example.com")
  #   result.claims["txn"] if result.ok?
  #
  # @param jwks [Hash, nil] an inline +{ "keys" => [...] }+ (offline); otherwise +jwks_url+ (default
  #   +<issuer>/.well-known/jwks.json+) is fetched and cached.
  # @param now [Time, nil]
  # @return [Atlas::TxnTokenResult]
  def verify_transaction_token(token, issuer:, trust_domain:, jwks: nil, jwks_url: nil, now: nil, fetch_impl: nil)
    require "jwt"
    iss = issuer.to_s.sub(%r{/+\z}, "")
    keys = jwks || txn_jwks_cache("#{jwks_url || "#{iss}/.well-known/jwks.json"}", fetch_impl).get(Atlas.read_kid(token.to_s))
    return txn_failure if keys.nil? || (keys["keys"] || keys[:keys]).to_a.empty?

    payload, header = JWS.decode(token.to_s, keys, algorithms: JWS::ALGORITHMS, iss: iss, aud: trust_domain, leeway: 5, verify_exp: now.nil?)
    return txn_failure unless header["typ"] == "txntoken+jwt"
    return txn_failure if now && payload["exp"].to_i + 5 <= now.to_i

    %w[txn sub scope req_wl iat exp].each do |claim|
      return TxnTokenResult.new(ok: false, error: "The transaction token has no #{claim}.") if payload[claim].nil?
    end
    TxnTokenResult.new(ok: true, claims: payload, scopes: payload["scope"].to_s.split.reject(&:empty?))
  rescue JWS::Error, ArgumentError
    txn_failure
  end

  def txn_failure
    TxnTokenResult.new(ok: false, error: "The transaction token is invalid, expired, or for another trust domain.")
  end

  def txn_jwks_cache(url, fetch_impl)
    TXN_JWKS_CACHES[url] ||= JwksCache.new(url: url, fetch_impl: fetch_impl)
  end

  TXN_JWKS_CACHES = {}
  private_constant :TXN_JWKS_CACHES
  private_class_method :txn_failure, :txn_jwks_cache
end
