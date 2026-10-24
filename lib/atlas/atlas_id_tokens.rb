# frozen_string_literal: true

require "json"
require "uri"

module Atlas
  # The browser route for integration tokens of Sign in with Atlas users:
  # +POST /v1/client/integrations/:id/atlas_id_tokens+. An app with no server of its own
  # gets a token for a service from a user's Sign in with Atlas access token. It is
  # normally called from browser code; this is the same call for a backend-for-frontend.
  #
  # The access token is sent as +Authorization: Bearer+, or with +dpop_proof:+ (a DPoP
  # proof for this exact request) as +DPoP+ — required when the token is DPoP-bound. Atlas
  # checks the +Origin+ against the Sign in with Atlas app's web origins, so pass +origin:+
  # when calling server-side. No cookies are sent.
  #
  #   token = Atlas::AtlasIdTokens.fetch(
  #     frontend_api: "https://clerk.example.com", publishable_key: "pk_live_...",
  #     integration: "referalli", access_token: user_access_token, origin: "https://app.example.com"
  #   )
  #   token["jwt"] if token
  module AtlasIdTokens
    module_function

    # @return [Hash, nil] +{"jwt", "expires_in", "integration", "audience", "issuer", "jwks_uri"}+,
    #   or +nil+ when the integration is not enabled for Sign in with Atlas users, the token
    #   is not accepted or the origin is not the app's.
    def fetch(frontend_api:, publishable_key:, integration:, access_token:, dpop_proof: nil, origin: nil, http: nil)
      return nil if access_token.to_s.empty?

      path = "/v1/client/integrations/#{URI.encode_www_form_component(integration).gsub('+', '%20')}/atlas_id_tokens"
      # The publishable key also rides in the query, so a CORS preflight can name the instance.
      url = "#{frontend_api.to_s.sub(%r{/+\z}, '')}#{path}?publishable_key=#{URI.encode_www_form_component(publishable_key)}"
      headers = { "Accept" => "application/json",
                  "Authorization" => "#{dpop_proof ? 'DPoP' : 'Bearer'} #{access_token}" }
      headers["DPoP"] = dpop_proof if dpop_proof
      headers["Origin"] = origin if origin
      status, text = (http || Atlas::NetHTTPRequester.new).call("POST", url, headers, nil)
      return nil unless status.between?(200, 299)

      data = JSON.parse(text.to_s)
      data.is_a?(Hash) && data["jwt"] ? data : nil
    rescue JSON::ParserError
      nil
    end
  end
end
