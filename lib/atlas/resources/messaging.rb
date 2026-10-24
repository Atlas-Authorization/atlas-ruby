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
      # +GET /v1/messaging_providers/:channel+ — one channel (+email+ / +sms+); 200 with
      # +configured: false+ when none is set up.
      def get_channel(channel)
        request(method: :get, path: "/v1/messaging_providers/#{enc(channel)}")
      end

      def get
        request(method: :get, path: "/v1/messaging_providers")
      end

      # Configure (or update) the email provider.
      #
      # @param body [Hash] +transport+ (one of {EMAIL_TRANSPORTS}), optional
      #   +from_address+, optional +mode+ (+"standard"+ | +"development"+), and
      #   +config+ with that transport's keys.
      # @return [Hash] the provider: +id+, +channel+, +mode+ (+"standard"+ |
      #   +"development"+ | +"managed_domain"+), +transport+, +from_address+,
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

      # +DELETE /v1/messaging_providers/:channel+ — remove the channel's provider.
      #
      # Removing the email provider is refused with a 409
      # +EMAIL_PROVIDER_IN_USE+ while email-dependent features are on and nothing
      # else would deliver email; the error's +meta["features"]+ lists them
      # (e.g. +"emailCode"+, +"emailLink"+, +"emailVerification"+,
      # +"passwordReset"+). Pass +force: true+ to remove it anyway.
      #
      # @param channel [String] +"email"+ or +"sms"+.
      # @param force [Boolean] send +?force=true+ (only sent when true).
      # @return [Hash] +{ "object" => "messaging_provider", "channel", "deleted" => true }+.
      def delete_channel(channel, force: false)
        request(method: :delete, path: "/v1/messaging_providers/#{enc(channel)}", query: force ? { force: true } : nil)
      end

      # Send a fixed, clearly-marked test message through the channel's provider.
      # +GET /v1/messaging_providers/email/managed+ — the managed sending domain:
      # +status+, +verified+, the DNS +records+ to publish and +usage+
      # (+limits+ is +nil+: your provider account's own limits apply). Also
      # +backend+, +provider_id+ and, on create, +feedback_webhook+. 404 when
      # none is configured.
      def get_managed_email
        request(method: :get, path: "/v1/messaging_providers/email/managed")
      end

      # +POST /v1/messaging_providers/email/managed+ — Atlas sets your sending
      # domain up on YOUR OWN Resend or Brevo account and sends through your key.
      #
      # @param body [Hash] +from_address+ (required; its domain is the sending
      #   domain), and +transport+ (+"resend"+ | +"brevo"+) with
      #   +config: { api_key: }+ (write-only), or +provider_id+ of your
      #   configured Resend or Brevo provider. Optional +region+ (Resend) and
      #   +dns+ (+{ provider: "cloudflare", api_token:, overwrite: }+: Atlas
      #   writes the records; the token is write-only).
      def create_managed_email(body)
        request(method: :post, path: "/v1/messaging_providers/email/managed", body: body)
      end

      # +POST /v1/messaging_providers/email/managed/verify+ — re-check the DNS records now.
      def verify_managed_email
        request(method: :post, path: "/v1/messaging_providers/email/managed/verify")
      end

      # +DELETE /v1/messaging_providers/email/managed+ — stop using managed email
      # (DNS records stay). Refused with 409 +EMAIL_PROVIDER_IN_USE+ while it is
      # the only way to send email; pass +force: true+ to remove it anyway.
      def delete_managed_email(force: false)
        request(method: :delete, path: "/v1/messaging_providers/email/managed", query: force ? { force: true } : nil)
      end

      # +GET /v1/messaging_providers/email/development+ — your email provider in
      # development mode: +provider_id+, +active+, +transport+, +from_address+,
      # +subject_prefix+, +footer+, +templates+ and +limits+ (+daily+,
      # +per_recipient_hourly+). 404 when it is not in development mode.
      def get_development_email
        request(method: :get, path: "/v1/messaging_providers/email/development")
      end

      # +POST /v1/messaging_providers/email/development+ — put your own email
      # provider in development mode, so a development instance sends Atlas's
      # sign-in emails without a verified domain (+[Atlas test] + subjects,
      # capped). 409 +DEVELOPMENT_EMAIL_NOT_ALLOWED+ on a production instance.
      #
      # @param body [Hash] +provider_id+, or +transport+ + +config+ (+
      #   +from_address+) exactly as {#set_email} takes them.
      def enable_development_email(body)
        request(method: :post, path: "/v1/messaging_providers/email/development", body: body)
      end

      # +DELETE /v1/messaging_providers/email/development+ — back to standard
      # mode (the provider and its key stay).
      def disable_development_email
        request(method: :delete, path: "/v1/messaging_providers/email/development")
      end

      def test(channel, body)
        request(method: :post, path: "/v1/messaging_providers/#{enc(channel)}/test", body: body)
      end
    end
  end
end
