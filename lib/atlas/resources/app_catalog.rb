# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class AppCatalog < Base
      # List the app presets: about 100 SAML apps (Slack, GitHub, Snowflake, Notion, HubSpot and
      # more) and about 45 OpenID Connect apps (Grafana, GitLab, Argo CD, Vault, Cloudflare Zero
      # Trust and more), each with its protocol, category, the parameters it needs, whether its
      # values were confirmed in the vendor's docs (verified) and that page (source_url).
      # Scope: app_catalog:read. query: limit, starting_after.
      def presets(query = nil)
        request(method: :get, path: "/v1/app_catalog", query: query)
      end

      # List the installed apps (SAML and OpenID Connect) with their email-domain allow-list and
      # assignment.
      # Scope: app_catalog:read. query: limit, starting_after.
      def installed(query = nil)
        request(method: :get, path: "/v1/app_catalog/installed", query: query)
      end

      # Install a catalog app from its preset and params, with an optional name, installed_id,
      # allowed_email_domains and assignment. A SAML preset becomes a SAML service provider; an OIDC
      # preset registers a confidential OAuth client with the preset's redirect URIs and returns
      # client_id, client_secret (shown once), redirect_uri and issuer to paste into the app. 409 if
      # the installed_id exists. → 201.
      # Scope: app_catalog:write. query: dry_run.
      def install(id, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/app_catalog/#{enc(id)}/install",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Change an installed app's name, allowed_email_domains or assignment. Assignment applies to
      # the launcher and to single sign-on: someone not assigned is refused with 403.
      # Scope: app_catalog:write. query: dry_run.
      def update(id, body, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/app_catalog/installed/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Uninstall an app: it disappears from the launcher and Atlas stops signing people in to it
      # (an OIDC app's OAuth client and its grants are deleted).
      # Scope: app_catalog:write. query: dry_run.
      def uninstall(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/app_catalog/installed/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
