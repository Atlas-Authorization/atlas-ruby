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

      # +/v1/platform/apps+ — apps (instances) your platform provisions and owns.
      class Apps < Base
        # +GET /v1/platform/apps+ — the apps this platform owns (include_archived:, archived:, tag:).
        def list(params = {})
          request(method: :get, path: "/v1/platform/apps", query: params)
        end

        # +POST /v1/platform/apps+ — provision a new app. Its secret key is returned once.
        def create(body = {}, idempotency_key: nil)
          request(method: :post, path: "/v1/platform/apps", body: body, idempotency_key: idempotency_key)
        end

        # +GET /v1/platform/apps/:id+ — one owned app.
        def get(id)
          request(method: :get, path: "/v1/platform/apps/#{enc(id)}")
        end

        # +PATCH /v1/platform/apps/:id+ — update an owned app's name, allowed_origins or tags.
        def update(id, body)
          request(method: :patch, path: "/v1/platform/apps/#{enc(id)}", body: body)
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
        def bulk_delete(ids)
          request(method: :post, path: "/v1/platform/apps/bulk_delete", body: { ids: ids })
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

        # +POST /v1/platform/apps/:id/instances/:instanceId/rotate_secret+ — rotate one instance's secret key (no overlap). The new secret is returned once.
        def rotate_instance_secret(id, instance_id, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/platform/apps/#{enc(id)}/instances/#{enc(instance_id)}/rotate_secret",
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

        # +POST /v1/platform/atlas_id_apps/:id/rotate_secret+ — rotate a confidential app's client_secret. The new secret is returned once; the old one works for 24 hours.
        def rotate_secret(id)
          request(method: :post, path: "/v1/platform/atlas_id_apps/#{enc(id)}/rotate_secret")
        end

        # +POST /v1/platform/atlas_id_apps/design/preview+ — preview a Sign in with Atlas app design without saving it.
        def preview_design(design)
          request(method: :post, path: "/v1/platform/atlas_id_apps/design/preview", body: { design: design })
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
