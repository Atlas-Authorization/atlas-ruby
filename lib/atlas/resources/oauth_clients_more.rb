# frozen_string_literal: true

require_relative "oauth_clients"

module Atlas
  module Resources
    class OAuthClients
      # Read the token-exchange policy of an OAuth client (the defaults, with configured=false, when
      # none is set).
      # Scope: oauth_clients:read.
      def get_exchange_policy(id)
        request(method: :get, path: "/v1/oauth_clients/#{enc(id)}/exchange_policy")
      end

      # Set the token-exchange policy of an OAuth client: allowed audiences and scopes, whether it
      # may impersonate (no actor_token), whether delegation needs may_act, and the maximum
      # act-chain depth. Audited as oauth_exchange_policy.updated.
      # Scope: oauth_clients:write. query: dry_run.
      def set_exchange_policy(id, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/oauth_clients/#{enc(id)}/exchange_policy",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Remove the token-exchange policy of an OAuth client, restoring the defaults.
      # Scope: oauth_clients:write. query: dry_run.
      def delete_exchange_policy(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/oauth_clients/#{enc(id)}/exchange_policy",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # Assign a policy profile to an OAuth client (profile null clears it). The client must already
      # conform (auth method, redirect URIs); the profile is then enforced at /oauth2/authorize,
      # /oauth2/par and /oauth2/token.
      # Scope: oauth_clients:write. query: dry_run. body requires: profile.
      def set_profile(id, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/oauth_clients/#{enc(id)}/profile",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Set (or clear, with null) the URLs of your own sign-in and consent pages for an OAuth
      # client. /oauth2/authorize then sends the browser there with a login_challenge /
      # consent_challenge instead of Atlas’s pages. A client URL overrides the instance-wide
      # oauthProvider.loginUrl / consentUrl.
      # Scope: oauth_clients:write. query: dry_run.
      def set_delegated_ui(id, body, query = nil, idempotency_key: nil)
        request(
          method: :put,
          path: "/v1/oauth_clients/#{enc(id)}/delegated_ui",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def app_settings
        @app_settings ||= AppSettings.new(@transport)
      end

      def workload_identity
        @workload_identity ||= WorkloadIdentity.new(@transport)
      end

      def trusted_issuers
        @trusted_issuers ||= TrustedIssuers.new(@transport)
      end

      def login_requests
        @login_requests ||= LoginRequests.new(@transport)
      end

      def consent_requests
        @consent_requests ||= ConsentRequests.new(@transport)
      end

      class AppSettings < Base
        # The per-application settings of an OAuth client: allowed sign-in methods, hosted-page
        # branding, the user-claim allow-list for ID tokens and userinfo, and the traits a session
        # from this app may write. Null = no restriction.
        # Scope: oauth_clients:read.
        def get(id)
          request(method: :get, path: "/v1/oauth_clients/#{enc(id)}/app_settings")
        end

        # Change the per-application settings. Each field sent replaces the stored one and null
        # clears it; fields left out keep their value. Unknown fields and malformed values are
        # refused.
        # Scope: oauth_clients:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/oauth_clients/#{enc(id)}/app_settings",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class WorkloadIdentity < Base
        # List the workload platforms Atlas knows defaults for (SPIFFE, Kubernetes, GitHub Actions,
        # GCP, Azure): issuer, JWKS URL and the shape of the token subject.
        # Scope: oauth_clients:read. query: limit, starting_after.
        def presets(query = nil)
          request(method: :get, path: "/v1/workload_identity/presets", query: query)
        end

        # Trust-policy snippets that make AWS (AssumeRoleWithWebIdentity), GCP (workload identity
        # federation) or Azure (federated credentials) accept an access token issued by this
        # instance. Nothing is changed in the cloud.
        # Scope: oauth_clients:read. query: provider (required), audience (required), subject
        # (required), tenant_id.
        def cloud_trust(query = nil)
          request(method: :get, path: "/v1/workload_identity/cloud_trust", query: query)
        end
      end

      class TrustedIssuers < Base
        # List the external issuers this OAuth client trusts to assert users through the RFC 7523
        # jwt-bearer grant.
        # Scope: oauth_clients:read. query: limit, starting_after.
        def list(id, query = nil)
          request(method: :get, path: "/v1/oauth_clients/#{enc(id)}/trusted_issuers", query: query)
        end

        # Trust an external issuer for this client. With purpose user_assertion (default) its signed
        # JWTs (verified against the inline jwks or the https jwks_uri) can then be presented to
        # POST /oauth2/token with grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer.
        # subject_mapping says how the JWT sub names an Atlas user. With purpose client_auth or both
        # (PRO-06 workload identity) a client registered with token_endpoint_auth_method
        # workload_jwt authenticates by presenting a token from this issuer as its client_assertion;
        # subject_pattern is then required and must name the workload. workload_kind github_actions,
        # gcp and azure fill in the issuer and JWKS URL. Audited as oauth_trusted_issuer.created.
        # Scope: oauth_clients:write. query: dry_run. body requires: issuer.
        def create(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/oauth_clients/#{enc(id)}/trusted_issuers",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Stop trusting an issuer: its assertions are refused at once. Audited as
        # oauth_trusted_issuer.deleted.
        # Scope: oauth_clients:write. query: dry_run.
        def delete(id, issuer_id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/oauth_clients/#{enc(id)}/trusted_issuers/#{enc(issuer_id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class LoginRequests < Base
        # Read a login challenge: which application is signing a user in, with what scopes, and who
        # (if anyone) is already signed in on this browser.
        # Scope: oauth_clients:read. query: login_challenge (required).
        def get(query = nil)
          request(method: :get, path: "/v1/oauth_login_requests", query: query)
        end

        # Accept a login challenge: the visitor authenticated as +subject+ (an Atlas user id).
        # Returns redirect_to; when the browser follows it Atlas signs the user in and continues the
        # authorization. The returned link is single-use and valid for five minutes.
        # Scope: oauth_clients:write. query: dry_run, login_challenge (required). body requires:
        # subject.
        def accept(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/oauth_login_requests/accept",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Reject a login challenge. Following redirect_to returns the application to its
        # redirect_uri with the OAuth error.
        # Scope: oauth_clients:write. query: dry_run, login_challenge (required).
        def reject(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/oauth_login_requests/reject",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class ConsentRequests < Base
        # Read a consent challenge: the signed-in user, the application and the scopes, audience,
        # authorization details and organization it asks for.
        # Scope: oauth_clients:read. query: consent_challenge (required).
        def get(query = nil)
          request(method: :get, path: "/v1/oauth_consent_requests", query: query)
        end

        # Accept a consent challenge, optionally narrowing the granted scopes. Following redirect_to
        # (in the same browser that started the flow) records the consent unless remember is false,
        # and returns the application to its redirect_uri with a code.
        # Scope: oauth_clients:write. query: dry_run, consent_challenge (required).
        def accept(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/oauth_consent_requests/accept",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Reject a consent challenge. Following redirect_to returns the application to its
        # redirect_uri with the OAuth error.
        # Scope: oauth_clients:write. query: dry_run, consent_challenge (required).
        def reject(body, query = nil, idempotency_key: nil)
          request(
            method: :put,
            path: "/v1/oauth_consent_requests/reject",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
