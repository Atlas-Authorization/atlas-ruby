# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # Platform-key (+psk_+) surface: apps you provision, Sign in with Atlas apps and their design images.
    #
    # Construct the client with your platform key to use it:
    #
    #   platform = Atlas::Client.new("psk_...").platform
    class Platform < Base
      def apps
        @apps ||= Apps.new(@transport)
      end

      def atlas_id_apps
        @atlas_id_apps ||= AtlasIdApps.new(@transport)
      end

      def design_assets
        @design_assets ||= DesignAssets.new(@transport)
      end

      def atlas_id_publisher
        @atlas_id_publisher ||= AtlasIdPublisher.new(@transport)
      end

      # +GET /v1/platform/whoami+ — introspect the platform key / token in use.
      def whoami
        request(method: :get, path: "/v1/platform/whoami")
      end

      # +/v1/platform/keys+ — every credential on the account and minting/revoking them.
      def keys
        @keys ||= Keys.new(@transport)
      end

      # +/v1/platform/audit_logs+ and +/v1/platform/audit_streams+ — the account audit log.
      def audit
        @audit ||= Audit.new(@transport)
      end

      class Keys < Base
        # +params+: +kind+, +status+, +instance_id+.
        def list(params = {})
          request(method: :get, path: "/v1/platform/keys", query: params.empty? ? nil : params)
        end

        # Body: +scopes+ (a subset of the caller's), +name+, +application_ids+, +expires_at+,
        # +ip_allowlist+, +owner+, +key_format+ (+atlas+ / +legacy+), +secret_recipient+.
        def create(body, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/keys", body: body, idempotency_key: idempotency_key)
        end

        def update(id, body)
          request(method: :patch, path: "/v1/platform/keys/#{enc(id)}", body: body)
        end

        def revoke(id)
          request(method: :post, path: "/v1/platform/keys/#{enc(id)}/revoke")
        end
      end

      class Audit < Base
        # +params+: +limit+, +starting_after+, +action+.
        def list(params = {})
          request(method: :get, path: "/v1/platform/audit_logs", query: params.empty? ? nil : params)
        end

        def streams
          @streams ||= Streams.new(@transport)
        end

        class Streams < Base
          def list
            request(method: :get, path: "/v1/platform/audit_streams")
          end

          def create(body)
            request(method: :post, path: "/v1/platform/audit_streams", body: body)
          end

          def update(id, body)
            request(method: :patch, path: "/v1/platform/audit_streams/#{enc(id)}", body: body)
          end

          def delete(id)
            request(method: :delete, path: "/v1/platform/audit_streams/#{enc(id)}")
          end

          def test(id)
            request(method: :post, path: "/v1/platform/audit_streams/#{enc(id)}/test")
          end
        end
      end

      # +GET /v1/platform/config_changelog+ — config change history for the
      # account's Sign in with Atlas apps (+action:+, +limit:+,
      # +starting_after:+, +since:+). Same entry shape as +config_changelog.list+.
      def config_changelog(params = {})
        request(method: :get, path: "/v1/platform/config_changelog", query: params)
      end

      # +/v1/platform/apps+ — apps (instances) your platform provisions and owns.
      class Apps < Base
        # +GET /v1/platform/apps+ — the apps this platform owns (include_archived:, archived:, tag:).
        # Also a +metadata:+ Hash filter (sent as +metadata[key]=value+).
        def list(params = {})
          request(method: :get, path: "/v1/platform/apps", query: Atlas::Resources.metadata_query(params))
        end

        # +POST /v1/platform/apps+ — provision a new app. Its secret key is returned once.
        # The body takes +external_ref+ and +metadata+; the response echoes them plus
        # +idempotent_replay+. +dry_run: true+ validates and writes nothing.
        def create(body = {}, idempotency_key: nil, dry_run: false)
          request(method: :post, path: "/v1/platform/apps", body: body, idempotency_key: idempotency_key,
                  query: Atlas::Resources.dry_run_query(dry_run))
        end

        # +GET /v1/platform/apps/:id+ — one owned app.
        def get(id)
          request(method: :get, path: "/v1/platform/apps/#{enc(id)}")
        end

        # +PATCH /v1/platform/apps/:id+ — update an owned app's name, allowed_origins or tags.
        # An +allowed_origins+ entry is an origin String or +{ origin:, integration: }+
        # (+"redirect"+ | +"embedded"+ | +"auto"+), as on +instance.update+. App objects
        # carry +frontend_api_host+, +issuer+, +discovery_url+, +jwks_uri+ and
        # +allowed_origin_integrations+.
        def update(id, body, dry_run: false)
          request(method: :patch, path: "/v1/platform/apps/#{enc(id)}", body: body, query: Atlas::Resources.dry_run_query(dry_run))
        end

        # +POST /v1/platform/apps/:id/secret_keys+ — mint an additional secret key for the app (revealed once).
        def create_secret_key(id, body = {}, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/apps/#{enc(id)}/secret_keys", body: body, idempotency_key: idempotency_key)
        end

        # +POST /v1/platform/apps/:id/clone_config+ — copy configuration from another app
        # (body: +from_app_id+ ... ). +dry_run: true+ previews.
        def clone_config(id, body, dry_run: false)
          request(method: :post, path: "/v1/platform/apps/#{enc(id)}/clone_config", body: body,
                  query: Atlas::Resources.dry_run_query(dry_run))
        end

        # +DELETE /v1/platform/apps/:id+ — disable an owned app (soft and reversible).
        def delete(id)
          request(method: :delete, path: "/v1/platform/apps/#{enc(id)}")
        end

        # +POST /v1/platform/apps/:id/archive+ — hide an owned app from the default listing (it keeps working).
        def archive(id)
          request(method: :post, path: "/v1/platform/apps/#{enc(id)}/archive")
        end

        # +POST /v1/platform/apps/:id/unarchive+ — return an archived app to the default listing.
        def unarchive(id)
          request(method: :post, path: "/v1/platform/apps/#{enc(id)}/unarchive")
        end

        # +POST /v1/platform/apps/bulk_delete+ — disable up to 100 owned apps in one call.
        # +metadata:+ selects apps by metadata instead of ids; +dry_run: true+ lists what would be deleted.
        def bulk_delete(ids = nil, metadata: nil, dry_run: false)
          body = {}
          body[:ids] = ids unless ids.nil?
          body[:metadata] = metadata unless metadata.nil?
          body[:dry_run] = true if dry_run
          request(method: :post, path: "/v1/platform/apps/bulk_delete", body: body)
        end

        # +POST /v1/platform/apps/:id/instances+ — provision an additional instance under an owned app. Its secret key is returned once.
        def create_instance(id, body = {}, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/#{enc(id)}/instances",
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +GET /v1/platform/apps/:id/instances+ — every instance under an owned app.
        def list_instances(id)
          request(method: :get, path: "/v1/platform/apps/#{enc(id)}/instances")
        end

        # +POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret+ — rotate one instance's secret key. The new
        # secret is returned once; the prior keys stay valid for +overlap_seconds+ (default 259200 = 72 hours, at most
        # 604800; +0+ revokes them now). The response carries +app_id+, +instance_id+, +overlap_seconds+ and
        # +previous_keys_expire_at+.
        def rotate_instance_secret(id, instance_id, body = Atlas::Transport::OMIT, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/#{enc(id)}/instances/#{enc(instance_id)}/rotate_secret",
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +POST /v1/platform/apps/:id/rotate_secret+ — rotate the app's secret key with an overlap window (overlap_seconds). The new secret is returned once.
        def rotate_secret(id, body = {}, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/#{enc(id)}/rotate_secret",
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # +GET /v1/platform/apps/:id/secret_keys+ — the app's currently valid secret keys (metadata only).
        def list_secret_keys(id)
          request(method: :get, path: "/v1/platform/apps/#{enc(id)}/secret_keys")
        end

        # +POST /v1/platform/apps/:id/transfer+ — start a transfer of an owned app; returns a one-time transfer_token.
        def transfer(id, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/apps/#{enc(id)}/transfer", idempotency_key: idempotency_key)
        end

        # +POST /v1/platform/apps/accept_transfer+ — accept an app transfer by its transfer_token.
        def accept_transfer(transfer_token, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/accept_transfer",
            body: { transfer_token: transfer_token },
            idempotency_key: idempotency_key
          )
        end

        # +POST /v1/platform/accountless_apps+ — mint an app owned by no platform and return a one-time claim_token.
        def create_accountless(body = {}, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/accountless_apps", body: body, idempotency_key: idempotency_key)
        end

        # +POST /v1/platform/apps/claim+ — claim an accountless app by its claim_token. Its secret key is returned once.
        def claim(claim_token, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/claim",
            body: { claim_token: claim_token },
            idempotency_key: idempotency_key
          )
        end
      end

      # +/v1/platform/atlas_id_apps+ — Sign in with Atlas apps (OpenID Connect clients) for your account.
      class AtlasIdApps < Base
        # +GET /v1/platform/atlas_id_apps+ — your Sign in with Atlas apps, with the issuer and discovery URL. Never a secret.
        def list
          request(method: :get, path: "/v1/platform/atlas_id_apps")
        end

        # +POST /v1/platform/atlas_id_apps+ — register a Sign in with Atlas app. A confidential app's client_secret is returned once.
        #
        # @param body [Hash]
        #   - +name+, +redirect_uris+ (exact-match https URLs; +http://localhost+ allowed);
        #   - +type+ — +"confidential"+ (default; gets a +client_secret+) or +"public"+ (PKCE, no secret);
        #   - +allowed_scopes+ — from +openid+ (always), +profile+, +email+, +offline_access+;
        #   - +logo_url+, +homepage_url+;
        #   - +post_logout_redirect_uris+ — where +/oauth2/logout+ may return to;
        #   - +backchannel_logout_uri+, +backchannel_logout_session_required+ —
        #     Atlas POSTs a +logout_token+ here when a user signs out (verify it
        #     with {Atlas::BackchannelLogout});
        #   - +frontchannel_logout_uri+, +frontchannel_logout_session_required+;
        #   - +branding+ — +theme+ (+auto+/+light+/+dark+), +accent_color+,
        #     +background_color+, +privacy_policy_url+, +terms_of_service_url+,
        #     +copy+ (+sign_in_title+, +sign_in_subtitle+, +sign_up_title+,
        #     +sign_up_subtitle+, +consent_message+, +support_url+,
        #     +support_label+; +{app}+ is replaced with the app name) and +design+
        #     (a full design; see {Atlas::Resources::Design}).
        #
        #   app = platform.atlas_id_apps.create(
        #     name: "Acme", redirect_uris: ["https://acme.com/callback"],
        #     backchannel_logout_uri: "https://acme.com/logout/backchannel",
        #     branding: { theme: "dark", accent_color: "#7c3aed" }
        #   )
        def create(body, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/atlas_id_apps", body: body, idempotency_key: idempotency_key)
        end

        # +GET /v1/platform/atlas_id_apps/:id+ — one Sign in with Atlas app, including user_count.
        def get(id)
          request(method: :get, path: "/v1/platform/atlas_id_apps/#{enc(id)}")
        end

        # +PATCH /v1/platform/atlas_id_apps/:id+ — update a Sign in with Atlas app (branding merges per field; nil clears).
        def update(id, body)
          request(method: :patch, path: "/v1/platform/atlas_id_apps/#{enc(id)}", body: body)
        end

        # +DELETE /v1/platform/atlas_id_apps/:id+ — delete a Sign in with Atlas app; its client_id stops working immediately.
        def delete(id)
          request(method: :delete, path: "/v1/platform/atlas_id_apps/#{enc(id)}")
        end

        # +POST /v1/platform/atlas_id_apps/:id/rotate_secret+ — rotate a confidential app's client_secret. The new secret
        # is returned once; the old one keeps working for +overlap_seconds+ (default 86400 = 24 hours; +0+ revokes it
        # now) until +previous_secret_expires_at+.
        def rotate_secret(id, body = Atlas::Transport::OMIT)
          request(method: :post, path: "/v1/platform/atlas_id_apps/#{enc(id)}/rotate_secret", body: body)
        end

        # +GET /v1/platform/atlas_id_apps/:id/backchannel_deliveries+ — the app's back-channel logout delivery log.
        def list_backchannel_deliveries(id, params = {})
          request(method: :get, path: "/v1/platform/atlas_id_apps/#{enc(id)}/backchannel_deliveries", query: params)
        end

        # +POST /v1/platform/atlas_id_apps/:id/backchannel_logout/test+ — send a test back-channel logout to the app now.
        def test_backchannel_logout(id)
          request(method: :post, path: "/v1/platform/atlas_id_apps/#{enc(id)}/backchannel_logout/test")
        end

        # +GET /v1/platform/atlas_id_apps/:id/preflight+ — check one app's setup (+ok+, +user_count+, +findings+, +button_rendered_origins+,
        # +authorize_requests_7d+, +fallback_origins+, +homepage_includes_script+).
        def preflight(id)
          request(method: :get, path: "/v1/platform/atlas_id_apps/#{enc(id)}/preflight")
        end

        # +GET /v1/platform/atlas_id_apps/:id/users?email=+ — privacy requests: is
        # this person one of the app's users? Exact match on a verified email;
        # returns +{ "data" => [{ "sub", "grant_id", "scopes", "granted_at" }] }+,
        # or an empty list for anyone else. The secret key of the instance that manages
        # the app (see +set_managed_by+) may call this route too; +atlas.atlas_id_apps.lookup+
        # is the same call on the instance client.
        def find_users(id, email)
          request(method: :get, path: "/v1/platform/atlas_id_apps/#{enc(id)}/users", query: { email: email })
        end

        # +DELETE /v1/platform/atlas_id_apps/:id/grants/:grant_id+ — revoke one
        # user's grant; the next sign-in shows the consent screen again. The secret key
        # of the instance that manages the app may call this route too.
        def revoke_grant(id, grant_id)
          request(method: :delete, path: "/v1/platform/atlas_id_apps/#{enc(id)}/grants/#{enc(grant_id)}")
        end

        # +POST /v1/platform/atlas_id_apps/:id/move_origin+ — move the app's URLs
        # from one origin to another (+from:+, +to:+, +dry_run:+).
        def move_origin(id, body)
          request(method: :post, path: "/v1/platform/atlas_id_apps/#{enc(id)}/move_origin", body: body)
        end

        # +PUT /v1/platform/atlas_id_apps/:id/managed_by+ — hand the app's grant management to an
        # instance of the same account (+managed_via: "adopted"+), or take it back with +nil+.
        # That instance's secret key, scoped to +privacy:grants:revoke+ or +atlas_id_apps:*+, then
        # lists and revokes the app's grants, so a data-rights tool never needs the platform key.
        # Returns the app plus +changed+.
        def set_managed_by(id, instance_id)
          request(method: :put, path: "/v1/platform/atlas_id_apps/#{enc(id)}/managed_by",
                  body: { instance_id: instance_id })
        end

        # +POST /v1/platform/atlas_id_apps/:id/webhook/rotate_secret+ — rotate the
        # app's webhook signing secret (+webhook_secret+, returned once). By default
        # the old secret stops signing at once; with +{ overlap_seconds: }+ it signs
        # each delivery too until +webhook_previous_secret_expires_at+.
        def rotate_webhook_secret(id, body = Atlas::Transport::OMIT)
          request(method: :post, path: "/v1/platform/atlas_id_apps/#{enc(id)}/webhook/rotate_secret", body: body)
        end

        # +POST /v1/platform/atlas_id_apps/design/preview+ — preview a Sign in with Atlas app design without saving it.
        def preview_design(design)
          request(method: :post, path: "/v1/platform/atlas_id_apps/design/preview", body: { design: design })
        end
      end

      # +/v1/platform/atlas_id_publisher+ — the account's Sign in with Atlas
      # publisher name and DNS-verified domain.
      class AtlasIdPublisher < Base
        # +GET /v1/platform/atlas_id_publisher+ — the publisher (404 until claimed).
        def get
          request(method: :get, path: "/v1/platform/atlas_id_publisher")
        end

        # +PUT /v1/platform/atlas_id_publisher+ — claim a publisher +name+ and
        # +domain+ (optional +skip_consent+); returns the TXT +verification+ record.
        def set(body)
          request(method: :put, path: "/v1/platform/atlas_id_publisher", body: body)
        end

        # +PATCH /v1/platform/atlas_id_publisher+ — turn publisher-wide consent on or off.
        def update(skip_consent:)
          request(method: :patch, path: "/v1/platform/atlas_id_publisher", body: { skip_consent: skip_consent })
        end

        # +DELETE /v1/platform/atlas_id_publisher+ — remove the publisher claim.
        def delete
          request(method: :delete, path: "/v1/platform/atlas_id_publisher")
        end

        # +POST /v1/platform/atlas_id_publisher/verify+ — look up the TXT record now (+record_found+).
        def verify
          request(method: :post, path: "/v1/platform/atlas_id_publisher/verify")
        end
      end

      # +/v1/platform/design/assets+ — design images for Sign in with Atlas app designs.
      class DesignAssets < Base
        # +GET /v1/platform/design/assets+ — design images owned by your platform account, newest first.
        def list
          request(method: :get, path: "/v1/platform/design/assets")
        end

        # +DELETE /v1/platform/design/assets/:id+ — delete a platform design image. Refused with 409 while a saved design uses it.
        def delete(asset_id)
          request(method: :delete, path: "/v1/platform/design/assets/#{enc(asset_id)}")
        end

        # +POST /v1/platform/design/assets+ — upload a design image owned by your
        # platform account: raw PNG, JPEG, GIF or WebP bytes, up to 8 MB. The
        # content type is detected from the bytes unless given.
        def upload(data, kind: nil, content_type: nil)
          upload_image("/v1/platform/design/assets", data, content_type, kind)
        end
      end
    end
  end
end
