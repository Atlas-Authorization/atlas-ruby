# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/email_templates+ — transactional email templates, keyed by name.
    class EmailTemplates < Base
      def list
        request(method: :get, path: "/v1/email_templates")
      end

      # Render an unsaved draft (if a body is given) or the stored template.
      def preview(name, body = {})
        request(method: :post, path: "/v1/email_templates/#{enc(name)}/preview", body: body)
      end

      # Save an override. Keyed by template name, not an id.
      def update(name, body)
        request(method: :put, path: "/v1/email_templates/#{enc(name)}", body: body)
      end

      # Revert to the built-in.
      def delete(name)
        request(method: :delete, path: "/v1/email_templates/#{enc(name)}")
      end
    end
  end
end
