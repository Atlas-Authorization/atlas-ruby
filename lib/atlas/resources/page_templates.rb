# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class PageTemplates < Base
      # The hosted-page templates of the instance: for each page (sign-in, sign-up, user-profile)
      # the live template and the draft waiting to be previewed or promoted.
      # Scope: instance:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/instance/page_templates", query: query)
      end

      # Read one page's live and draft template.
      # Scope: instance:read.
      def get(page)
        request(method: :get, path: "/v1/instance/page_templates/#{enc(page)}")
      end

      # Save a page template as the page's draft. A template is data: components (heading, text,
      # image, link, button_link, list, divider, spacer, columns) in four regions (header,
      # above_form, below_form, footer). It is validated on save: no raw HTML, CSS or script, https
      # and mailto links only. The live page is unchanged until you promote.
      # Scope: instance:write. query: dry_run.
      def save_draft(page, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/instance/page_templates/#{enc(page)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Drop the draft or take the live template down (+status+).
      # Scope: instance:write. query: dry_run, status.
      def discard(page, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/instance/page_templates/#{enc(page)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # A signed link to the hosted page with the draft template applied (valid for one hour,
      # noindex, with a preview banner). 409 when the page has no template.
      # Scope: instance:read. query: dry_run.
      def preview(page, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/instance/page_templates/#{enc(page)}/preview",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Make the draft the live template.
      # Scope: instance:write. query: dry_run.
      def promote(page, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/instance/page_templates/#{enc(page)}/promote",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
