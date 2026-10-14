# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/messaging_providers+ — use your own email or SMS provider. Provider
    # secrets are write-only: a response reports only which secret keys are set
    # (+secrets_set+), never their values.
    #
    # Each transport accepts an exact set of +config+ keys, listed in
    # {EMAIL_TRANSPORTS} and {SMS_TRANSPORTS}; the API refuses any other key
    # with a 422 naming +config.<key>+. +required+ keys must be sent the first
    # time you configure a transport (or switch the channel to it). On an update
    # of the SAME transport an omitted (or +""+) key keeps its stored value —
    # including a stored secret — so a from-address change need not re-send the
    # API key. +secrets+ are write-only.
    #
    #   atlas.messaging.set_email(
    #     transport: "mailgun", from_address: "Acme <no-reply@acme.com>",
    #     config: { api_key: "key-...", domain: "mg.acme.com", region: "eu" }
    #   )
    #   atlas.messaging.set_sms(transport: "twilio", config: { account_sid: "AC...", auth_token: "...", from: "+15550001111" })
    class Messaging < Base
      # Email transports and their +config+ keys.
      EMAIL_TRANSPORTS = {
        "resend" => { required: %w[api_key], optional: [], secrets: %w[api_key] },
        "brevo" => { required: %w[api_key], optional: [], secrets: %w[api_key] },
        "mailgun" => { required: %w[api_key domain], optional: %w[region], secrets: %w[api_key] },
        "ses" => { required: %w[region access_key_id secret_access_key], optional: %w[session_token],
                   secrets: %w[access_key_id secret_access_key session_token] },
        "smtp" => { required: %w[host], optional: %w[port secure username password], secrets: %w[password] }
      }.freeze

      # SMS transports and their +config+ keys (each also accepts an optional +from+).
      SMS_TRANSPORTS = {
        "twilio" => { required: %w[account_sid auth_token], optional: %w[from whatsapp_from voice_from],
                      secrets: %w[auth_token] },
        "vonage" => { required: %w[api_key api_secret], optional: %w[from], secrets: %w[api_secret] },
        "messagebird" => { required: %w[access_key], optional: %w[from], secrets: %w[access_key] },
        "plivo" => { required: %w[auth_id auth_token], optional: %w[from], secrets: %w[auth_token] },
        "telnyx" => { required: %w[api_key], optional: %w[from], secrets: %w[api_key] },
        "sinch" => { required: %w[service_plan_id api_token], optional: %w[region from], secrets: %w[api_token] },
        "infobip" => { required: %w[base_url api_key], optional: %w[from], secrets: %w[api_key] },
        "clicksend" => { required: %w[username api_key], optional: %w[from], secrets: %w[api_key] },
        "bandwidth" => { required: %w[account_id application_id username password], optional: %w[from],
                         secrets: %w[password] },
        "aws_sns" => { required: %w[region access_key_id secret_access_key], optional: %w[session_token from],
                       secrets: %w[secret_access_key session_token] }
      }.freeze

      # The config keys a transport accepts (required + optional), or nil for an
      # unknown transport. Useful for validating input before sending it.
      def self.config_keys(channel, transport)
        table = channel.to_s == "sms" ? SMS_TRANSPORTS : EMAIL_TRANSPORTS
        entry = table[transport.to_s]
        entry && (entry[:required] + entry[:optional])
      end

      # The instance's configured email and SMS providers, secrets omitted.
      def get
        request(method: :get, path: "/v1/messaging_providers")
      end

      # Configure (or update) the email provider.
      #
      # @param body [Hash] +transport+ (one of {EMAIL_TRANSPORTS}), optional
      #   +from_address+, and +config+ with that transport's keys.
      # @return [Hash] the provider: +channel+, +transport+, +from_address+,
      #   +status+, +config+ (non-secret values), +secrets_set+, +updated_at+.
      def set_email(body)
        request(method: :put, path: "/v1/messaging_providers/email", body: body)
      end

      # Configure (or update) the SMS provider.
      #
      # @param body [Hash] +transport+ (one of {SMS_TRANSPORTS}), optional
      #   +from_address+, and +config+ with that transport's keys.
      # @return [Hash] the provider (see {#set_email}).
      def set_sms(body)
        request(method: :put, path: "/v1/messaging_providers/sms", body: body)
      end

      def delete_channel(channel)
        request(method: :delete, path: "/v1/messaging_providers/#{enc(channel)}")
      end

      # Send a fixed, clearly-marked test message through the channel's provider.
      def test(channel, body)
        request(method: :post, path: "/v1/messaging_providers/#{enc(channel)}/test", body: body)
      end
    end
  end
end
