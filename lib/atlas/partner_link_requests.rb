# frozen_string_literal: true

require "json"
require "uri"

module Atlas
  # The partner product's side of the partner-link request protocol
  # (+atlas.partner_link_request.v1+). A partner needs no Atlas credential: it asks an
  # instance for a link, the owner approves it ({Atlas::Resources::PartnerLinks::Requests}),
  # and Atlas POSTs the credentials (or a denial) to the partner's +callback_url+, signed
  # with the +request_secret+ returned at creation.
  #
  #   created = Atlas::PartnerLinkRequests.create(
  #     partner: "acme", resource: "ins_123", scopes: ["privacy:execute"],
  #     callback_url: "https://acme.example/atlas/callback"
  #   )
  #   store(created["id"], created["request_secret"]) # shown once
  #
  #   # in the callback route:
  #   result = Atlas::PartnerLinkRequests.verify_delivery(
  #     body: request.raw_post, headers: request.headers, request_secret: stored_secret
  #   )
  #   if result.verified? && result.event["object"] == "partner_link.credentials"
  #     save(result.event["client_id"], result.event["client_secret"])
  #   end
  module PartnerLinkRequests
    PROTOCOL = "atlas.partner_link_request.v1"

    module_function

    # +POST /v1/partner_link_requests+ — ask an instance for a link. +body+: +partner+,
    # +resource+ (+ins_...+ or a publishable key), +scopes+, +callback_url+, and optionally
    # +name+, +state+, +cert_fingerprints+. Returns the request with its one-time
    # +request_secret+. Raises {Atlas::APIError} when Atlas refuses.
    def create(body = nil, api_url: Atlas::DEFAULT_API_URL, http: nil, **fields)
      payload = body || fields
      status, text = send_request("POST", "#{api_url.to_s.sub(%r{/+\z}, '')}/v1/partner_link_requests",
                                  { "Content-Type" => "application/json" }, JSON.generate(payload), http)
      parse(status, text)
    end

    # +GET /v1/partner_link_requests/:id+ — the status of a request, read with its
    # +request_secret+.
    def get(id, request_secret:, api_url: Atlas::DEFAULT_API_URL, http: nil)
      status, text = send_request("GET", "#{api_url.to_s.sub(%r{/+\z}, '')}/v1/partner_link_requests/#{URI.encode_www_form_component(id)}",
                                  { "Authorization" => "Bearer #{request_secret}" }, nil, http)
      parse(status, text)
    end

    # Verify and parse what Atlas delivered to your callback: +partner_link.credentials+ or
    # +partner_link.denied+. Returns an {Atlas::Webhook::Result} (+event+ is the delivery).
    # Pass +url:+ (your callback URL) to also accept the URL-bound +v2+ signature.
    def verify_delivery(body:, headers:, request_secret:, **opts)
      Atlas::Webhook.verify(body: body, headers: headers, secret: request_secret, **opts)
    end

    def send_request(verb, url, headers, body, http)
      requester = http || Atlas::NetHTTPRequester.new
      all = { "Accept" => "application/json" }.merge(headers)
      result = requester.call(verb, url, all, body)
      [result[0], result[1]]
    end
    private_class_method :send_request

    def parse(status, text)
      data = text.to_s.empty? ? {} : JSON.parse(text)
      unless status.between?(200, 299)
        errors = data.is_a?(Hash) ? data["errors"] : nil
        raise Atlas::ErrorFactory.build(status, errors.is_a?(Array) ? errors : [{ "code" => "UNKNOWN", "message" => text.to_s[0, 500] }])
      end
      data
    rescue JSON::ParserError
      raise Atlas::ErrorFactory.build(status, [{ "code" => "UNKNOWN", "message" => text.to_s[0, 500] }])
    end
    private_class_method :parse
  end
end
