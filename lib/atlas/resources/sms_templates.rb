# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/sms_templates+ — transactional SMS templates, keyed by name.
    class SmsTemplates < Base
      def list
        request(method: :get, path: "/v1/sms_templates")
      end

      # Upsert an override by name.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/sms_templates", body: body, idempotency_key: idempotency_key)
      end

      def get(name)
        request(method: :get, path: "/v1/sms_templates/#{enc(name)}")
      end

      def update(name, body)
        request(method: :patch, path: "/v1/sms_templates/#{enc(name)}", body: body)
      end

      # Revert to the built-in.
      def delete(name)
        request(method: :delete, path: "/v1/sms_templates/#{enc(name)}")
      end

      # Render an unsaved draft (if a body is given) or the stored/built-in.
      def preview(name, body = {})
        request(method: :post, path: "/v1/sms_templates/#{enc(name)}/preview", body: body)
      end
    end
  end
end
