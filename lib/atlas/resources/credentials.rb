# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +GET /v1/whoami+ — introspect the key this client authenticates with
    # (kind, scopes, expiry, owner, instance). Callable as +atlas.whoami.get+.
    class Whoami < Base
      def get
        request(method: :get, path: "/v1/whoami")
      end
      alias call get
    end

    # +/v1/secret_keys+ — the instance's secret keys: mint, list, rotate, revoke.
    # A new secret is revealed exactly once (as +secret+, or +sealed_secret+ when
    # +secret_recipient+ — a base64 X25519 public key — is given; open it with
    # libsodium +crypto_box_seal_open+).
    class SecretKeys < Base
      # @param body [Hash] +name+, +scopes+, +owner+ (defaults to the creator),
      #   +expires_at+ (defaults to one year; never longer, +nil+ is refused),
      #   +allowed_origins+ (browser origins the key is locked to; a call from another
      #   origin is refused with +ORIGIN_NOT_ALLOWED+), +allowed_ips+,
      #   +key_format+ (+"atlas"+ default, or +"legacy"+ for +sk_+), +secret_recipient+,
      #   +external_ref+, +metadata+.
      def create(body, idempotency_key: nil, dry_run: false)
        request(method: :post, path: "/v1/secret_keys", body: body, idempotency_key: idempotency_key,
                query: Atlas::Resources.dry_run_query(dry_run))
      end

      def list(params = {})
        request(method: :get, path: "/v1/secret_keys", query: Atlas::Resources.metadata_query(params))
      end

      def get(id)
        request(method: :get, path: "/v1/secret_keys/#{enc(id)}")
      end

      # +name+, +owner+, +expires_at+, +allowed_ips+, +metadata+.
      def update(id, body)
        request(method: :patch, path: "/v1/secret_keys/#{enc(id)}", body: body)
      end

      # New key with the same scopes; the old one keeps working for +overlap_seconds+
      # (default 72 h, 0 = revoke now). Also +key_format+.
      def rotate(id, body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/secret_keys/#{enc(id)}/rotate", body: body, idempotency_key: idempotency_key)
      end

      def revoke(id)
        request(method: :post, path: "/v1/secret_keys/#{enc(id)}/revoke")
      end
    end

    # Keys across kinds, the operator document and leaked-key revocation.
    class Keys < Base
      # +GET /v1/keys+ — every credential on the instance, standard shape.
      def list(params = {})
        request(method: :get, path: "/v1/keys", query: params.empty? ? nil : params)
      end

      # +POST /v1/keys/revoke_leaked+ — revoke leaked Atlas credentials. Needs no key
      # (the leaked secret is the proof), so it works with any client.
      def revoke_leaked(body)
        request(method: :post, path: "/v1/keys/revoke_leaked", body: body)
      end

      # +GET /v1/operator+ — where the operator device flow and token exchange live, the
      # other products that accept Atlas operators (+audiences+) and the claims an operator
      # access token carries (+access_token_claims+).
      def operator
        request(method: :get, path: "/v1/operator")
      end

      # +POST /v1/oauth/token+ — token exchange (RFC 8693, +grant_type+
      # +urn:ietf:params:oauth:grant-type:token-exchange+) or +client_credentials+.
      # Sent form-encoded, as the OAuth endpoint requires.
      def exchange_token(params)
        form = URI.encode_www_form(params.reject { |_k, v| v.nil? })
        request(method: :post, path: "/v1/oauth/token", raw_body: form, content_type: "application/x-www-form-urlencoded")
      end
      alias oauth_token exchange_token

      # Convenience: a +client_credentials+ grant.
      def client_credentials(client_id:, client_secret:, scope: nil, audience: nil)
        exchange_token(grant_type: "client_credentials", client_id: client_id, client_secret: client_secret,
                       scope: scope, audience: audience)
      end

      # Convenience: an RFC 8693 token exchange.
      def token_exchange(subject_token:, subject_token_type: "urn:ietf:params:oauth:token-type:access_token", **rest)
        exchange_token({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                         subject_token: subject_token, subject_token_type: subject_token_type }.merge(rest))
      end
    end

    # +/v1/partner_links+ — scoped credentials granted to a partner product, and
    # the outbound links this instance holds into partner products.
    class PartnerLinks < Base
      # Create a link by hand (the secret is returned once). Prefer approving a
      # partner's request ({#requests}): there is no secret to hand over.
      #
      # @param body [Hash] +partner+, +name+, +scopes+, +expires_at+, +cert_fingerprints+.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/partner_links", body: body, idempotency_key: idempotency_key)
      end

      # Lock a link to client certificates (mTLS); an empty array removes the lock.
      def set_certificates(id, cert_fingerprints)
        request(method: :patch, path: "/v1/partner_links/#{enc(id)}", body: { cert_fingerprints: Array(cert_fingerprints) })
      end

      # Partner link requests: a partner asks, you approve or deny, and Atlas delivers
      # the credentials to the partner's callback (you never see the secret).
      def requests
        @requests ||= Requests.new(@transport)
      end

      def list
        request(method: :get, path: "/v1/partner_links")
      end

      def get(id)
        request(method: :get, path: "/v1/partner_links/#{enc(id)}")
      end

      def rotate_secret(id)
        request(method: :post, path: "/v1/partner_links/#{enc(id)}/rotate_secret")
      end

      def revoke(id)
        request(method: :delete, path: "/v1/partner_links/#{enc(id)}")
      end

      def outbound
        @outbound ||= Outbound.new(@transport)
      end

      class Requests < Base
        # +direction:+ (+inbound+ / +outbound+), +status:+ (a String or an Array).
        def list(params = {})
          q = params.dup
          q[:status] = Array(q[:status]).join(",") if q.key?(:status)
          request(method: :get, path: "/v1/partner_links/requests", query: q.empty? ? nil : q)
        end

        def get(id)
          request(method: :get, path: "/v1/partner_links/requests/#{enc(id)}")
        end

        # Approve: Atlas creates the link and delivers its credentials to the partner,
        # signed. +scopes+ may narrow the request, never widen it; +expires_at+.
        def approve(id, body = {})
          request(method: :post, path: "/v1/partner_links/requests/#{enc(id)}/approve", body: body)
        end

        def deny(id)
          request(method: :post, path: "/v1/partner_links/requests/#{enc(id)}/deny")
        end
      end

      class Outbound < Base
        # Each link's +source+ is +manual+, +oauth_install+ (delivered by the partner) or
        # +registration+ (a partner platform's stored partner token).
        def list
          request(method: :get, path: "/v1/partner_links/outbound")
        end

        # Ask a partner for a link; its credentials arrive by themselves once the
        # partner approves. +body+: +scopes+, optionally +resource+, +base_url+,
        # +token_url+, +name+.
        def request_link(partner, body)
          request(method: :post, path: "/v1/partner_links/outbound/#{enc(partner)}/request", body: body)
        end

        def save(partner, body)
          request(method: :put, path: "/v1/partner_links/outbound/#{enc(partner)}", body: body)
        end

        def test(partner)
          request(method: :post, path: "/v1/partner_links/outbound/#{enc(partner)}/test")
        end

        def remove(partner)
          request(method: :delete, path: "/v1/partner_links/outbound/#{enc(partner)}")
        end
      end
    end

    # +/v1/atlas_id_apps+ on the secret-key surface — Sign in with Atlas apps this
    # instance manages and their grants.
    class AtlasIdGrants < Base
      # The apps this instance manages: +managed_via+ (+instance_toggle+ or +adopted+) and
      # +button_rendered_origins+ on each.
      def list_apps
        request(method: :get, path: "/v1/atlas_id_apps")
      end

      # +GET /v1/atlas_id_apps/:id/preflight+ — the setup check of an app this instance manages
      # (+diagnostics:read+ is enough): +ok+, +findings+, +button_rendered_origins+,
      # +authorize_requests_7d+, +fallback_origins+, +homepage_includes_script+.
      def preflight(app_id)
        request(method: :get, path: "/v1/atlas_id_apps/#{enc(app_id)}/preflight")
      end

      # Is this verified email a user of the app? An empty list otherwise.
      def lookup(app_id, email)
        request(method: :get, path: "/v1/atlas_id_apps/#{enc(app_id)}/users", query: { email: email })
      end

      def revoke_grant(app_id, grant_id)
        request(method: :delete, path: "/v1/atlas_id_apps/#{enc(app_id)}/grants/#{enc(grant_id)}")
      end
    end

    # Query helpers shared by the v2 resources.

    # The query of a per-call audience: the integration's own parameters, +cbid+, +audience+.
    def self.audience_query(audience: nil, cbid: nil, params: nil)
      q = {}
      (params || {}).each { |k, v| q[k.to_sym] = v unless v.nil? || v.to_s.empty? }
      q[:cbid] = cbid if cbid && !cbid.to_s.empty?
      q[:audience] = audience if audience && !audience.to_s.empty?
      q.empty? ? nil : q
    end
    def self.dry_run_query(dry_run)
      dry_run ? { dry_run: true } : nil
    end

    # Flatten a +metadata:+ Hash filter into +metadata[key]=value+ query pairs.
    def self.metadata_query(params)
      return nil if params.nil? || params.empty?

      out = {}
      params.each do |k, v|
        if k.to_s == "metadata" && v.is_a?(Hash)
          v.each { |mk, mv| out["metadata[#{mk}]"] = mv }
        else
          out[k] = v
        end
      end
      out
    end
  end
end
