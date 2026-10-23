# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # The community Actions gallery: browse reusable Action templates
    # (first-party and community), install one as a DISABLED action, and keep
    # installed actions up to date.
    class ActionGallery < Base
      # +q:+, +category:+, +trigger:+, +source:+ ("builtin" | "community").
      def list(params = nil)
        request(method: :get, path: "/v1/action_gallery", query: params)
      end

      # One template with its code, secret names and versions.
      def get(slug)
        request(method: :get, path: "/v1/action_gallery/#{enc(slug)}")
      end

      # Install as a new, disabled action: +{ version:, name:, secrets: {} }+.
      # Supply secrets, bind it, then enable it.
      def install(slug, body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/action_gallery/#{enc(slug)}/install", body: body,
                idempotency_key: idempotency_key)
      end

      # Actions installed from the gallery, with update status.
      def installs
        request(method: :get, path: "/v1/action_gallery_installs")
      end

      # Move an installed action to its template's latest version.
      def update(action_id, secrets: nil)
        request(method: :post, path: "/v1/actions/#{enc(action_id)}/gallery_update",
                body: secrets ? { secrets: secrets } : {})
      end
    end

    # Templates this instance publishes to the gallery (staff review them).
    class ActionTemplates < Base
      def list
        request(method: :get, path: "/v1/action_templates")
      end

      # +{ slug:, name:, author_name:, trigger:, ... }+, optionally with the first
      # version (+version:+, +code:+, +secrets:+, +changelog:+, +submit:+).
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/action_templates", body: body, idempotency_key: idempotency_key)
      end

      def get(id)
        request(method: :get, path: "/v1/action_templates/#{enc(id)}")
      end

      def update(id, body)
        request(method: :patch, path: "/v1/action_templates/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/action_templates/#{enc(id)}")
      end

      # +{ version:, code:, secrets:, changelog:, submit: }+ (MAJOR.MINOR.PATCH,
      # higher than every existing version).
      def add_version(id, body)
        request(method: :post, path: "/v1/action_templates/#{enc(id)}/versions", body: body)
      end

      def submit_version(id, version)
        request(method: :post, path: "/v1/action_templates/#{enc(id)}/versions/#{enc(version)}/submit")
      end

      def delete_version(id, version)
        request(method: :delete, path: "/v1/action_templates/#{enc(id)}/versions/#{enc(version)}")
      end

      # List an approved template again after unlisting it.
      def publish(id)
        request(method: :post, path: "/v1/action_templates/#{enc(id)}/publish")
      end

      # Hide a template from the gallery (installs keep working).
      def unlist(id)
        request(method: :post, path: "/v1/action_templates/#{enc(id)}/unlist")
      end
    end
  end
end
