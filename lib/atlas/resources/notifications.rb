# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/notifications+ — templated notification emails and their categories and templates.
    class Notifications < Base
      def categories
        @categories ||= Categories.new(@transport)
      end

      def templates
        @templates ||= Templates.new(@transport)
      end

      # +POST /v1/notifications+ — send a templated notification email to a user, honouring their preferences. Returns sent or suppressed.
      def create(body)
        request(method: :post, path: "/v1/notifications", body: body)
      end

      # +/v1/notification_categories+ — your notification categories (each a user preference toggle).
      class Categories < Base
        # +GET /v1/notification_categories+ — your notification categories.
        def list
          request(method: :get, path: "/v1/notification_categories")
        end

        # +POST /v1/notification_categories+ — create a notification category (key, label).
        def create(body)
          request(method: :post, path: "/v1/notification_categories", body: body)
        end

        # +PUT /v1/notification_categories/:key+ — change a category's label.
        def update(key, label)
          request(method: :put, path: "/v1/notification_categories/#{enc(key)}", body: { label: label })
        end

        # +DELETE /v1/notification_categories/:key+ — delete a category (refused while a template uses it).
        def delete(key)
          request(method: :delete, path: "/v1/notification_categories/#{enc(key)}")
        end
      end

      # +/v1/notification_templates+ — your notification email templates.
      class Templates < Base
        # +GET /v1/notification_templates+ — your notification templates.
        def list
          request(method: :get, path: "/v1/notification_templates")
        end

        # +POST /v1/notification_templates+ — create a notification template (name, subject, body, category).
        def create(body)
          request(method: :post, path: "/v1/notification_templates", body: body)
        end

        # +GET /v1/notification_templates/:name+ — one notification template by name.
        def get(name)
          request(method: :get, path: "/v1/notification_templates/#{enc(name)}")
        end

        # +PUT /v1/notification_templates/:name+ — update a template's subject, body and category.
        def update(name, body)
          request(method: :put, path: "/v1/notification_templates/#{enc(name)}", body: body)
        end

        # +DELETE /v1/notification_templates/:name+ — delete a notification template.
        def delete(name)
          request(method: :delete, path: "/v1/notification_templates/#{enc(name)}")
        end
      end
    end
  end
end
