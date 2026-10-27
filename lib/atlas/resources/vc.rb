# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Vc < Base
      # Create a wallet offer for a user (pre-authorized code flow). The response carries the code
      # once, as an openid-credential-offer:// link.
      # Scope: vc:write. query: dry_run. body requires: credential_type_id, user_id.
      def create_offer(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/vc/offers",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      def credential_types
        @credential_types ||= CredentialTypes.new(@transport)
      end

      def credentials
        @credentials ||= Credentials.new(@transport)
      end

      def presentation_requests
        @presentation_requests ||= PresentationRequests.new(@transport)
      end

      class CredentialTypes < Base
        # List the credential types you issue.
        # Scope: vc:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/vc/credential_types", query: query)
        end

        # Define a credential type: its vct, and how each claim is filled from a user’s attributes.
        # Issued as SD-JWT VC.
        # Scope: vc:write. query: dry_run. body requires: vct, name, claims.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/vc/credential_types",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read one credential type.
        # Scope: vc:read.
        def get(id)
          request(method: :get, path: "/v1/vc/credential_types/#{enc(id)}")
        end

        # Delete a credential type and the records of what was issued under it.
        # Scope: vc:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/vc/credential_types/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end
      end

      class Credentials < Base
        # List issued credentials (most recent 200), optionally for one user.
        # Scope: vc:read. query: user_id, limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/vc/credentials", query: query)
        end

        # Revoke an issued credential: its status-list bit is set and later presentations are
        # refused.
        # Scope: vc:write. query: dry_run.
        def revoke(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/vc/credentials/#{enc(id)}/revoke",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end

      class PresentationRequests < Base
        # Start a verifier request for a credential type and claims. Show authorization_request_uri
        # to the wallet, then read the request for the outcome.
        # Scope: vc:write. query: dry_run. body requires: vct.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/vc/presentation_requests",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Read a presentation request and its outcome.
        # Scope: vc:read.
        def get(id)
          request(method: :get, path: "/v1/vc/presentation_requests/#{enc(id)}")
        end
      end
    end
  end
end
