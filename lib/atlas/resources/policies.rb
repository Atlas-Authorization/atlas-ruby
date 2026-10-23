# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/policies+ — policy acceptance: the policies (Terms of Service,
    # privacy policy, any key) your users accept at sign-up and, per policy,
    # again at sign-in when a new version takes effect. A policy's versions go
    # draft, published (with an +effective_at+), retired. Acceptances are
    # append-only evidence (version, content hash, how it was shown). Wherever
    # +id_or_key+ is taken, the policy id or its key works.
    #
    #   atlas.policies.create({ key: "tos", title: "Terms of Service", applies_to: "sign_in_and_sign_up" })
    #   atlas.policies.versions.create("tos", { version: "2026-10-24", content_markdown: "# Terms" })
    #   atlas.policies.versions.publish("tos", "2026-10-24", { effective_at: "2026-11-01T00:00:00Z" })
    class Policies < Base
      # +GET /v1/policies+ — active policies (+include_retired: true+ for all), each with its current, upcoming and latest version.
      def list(params = {})
        request(method: :get, path: "/v1/policies", query: params)
      end

      # +POST /v1/policies+ — create a policy (+key+, +title+; optional +display+ checkbox|scroll|link,
      # +required+, +applies_to+ sign_up|sign_in_and_sign_up, +reaccept+ none|next_sign_in|grace with +grace_days+, +position+).
      # It asks nobody anything until a version is published.
      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/policies", body: body, idempotency_key: idempotency_key)
      end

      # +GET /v1/policies/:id+ — one policy, by id or key.
      def get(id_or_key)
        request(method: :get, path: "/v1/policies/#{enc(id_or_key)}")
      end

      # +PATCH /v1/policies/:id+ — update a policy (the key cannot change). +status: "retired"+ stops it gating (history is kept); +"active"+ brings it back.
      def update(id_or_key, body, idempotency_key: nil)
        request(method: :patch, path: "/v1/policies/#{enc(id_or_key)}", body: body, idempotency_key: idempotency_key)
      end

      # +DELETE /v1/policies/:id+ — delete a never-published policy; one with a published version is retired instead (check +deleted+ / +retired+).
      def delete(id_or_key)
        request(method: :delete, path: "/v1/policies/#{enc(id_or_key)}")
      end

      # +GET /v1/policies/:id/acceptances+ — who accepted the policy, newest first, with the evidence.
      # +params+: +version+ (id or label), +status+ (accepted | withdrawn | all), +limit+, +starting_after+.
      def list_acceptances(id_or_key, params = {})
        request(method: :get, path: "/v1/policies/#{enc(id_or_key)}/acceptances", query: params)
      end

      # The same as CSV text (+format=csv+, up to 100,000 rows).
      def export_acceptances_csv(id_or_key, params = {})
        query = params.reject { |k, _| %w[limit starting_after].include?(k.to_s) }.merge(format: "csv")
        request(method: :get, path: "/v1/policies/#{enc(id_or_key)}/acceptances", query: query, raw: true)
      end

      # +GET /v1/users/:id/policies+ — a user's standing on every policy (accepted and current version,
      # +needs_reaccept+, +blocking+, +grace_ends_at+) and +needs_acceptance+.
      def for_user(user_id)
        request(method: :get, path: "/v1/users/#{enc(user_id)}/policies")
      end

      def versions
        @versions ||= Versions.new(@transport)
      end

      def settings
        @settings ||= Settings.new(@transport)
      end

      # +/v1/policies/:id/versions+.
      class Versions < Base
        # +GET /v1/policies/:id/versions+ — newest first, each with +acceptance_count+.
        def list(id_or_key)
          request(method: :get, path: "/v1/policies/#{enc(id_or_key)}/versions")
        end

        # +POST /v1/policies/:id/versions+ — a draft, or published at once with +publish: true+ (and +effective_at+).
        # +content_markdown+ is rendered and sanitised, +content_html+ is sanitised. 400 for an external policy (its versions come from the policy source).
        def create(id_or_key, body, idempotency_key: nil)
          request(method: :post, path: "/v1/policies/#{enc(id_or_key)}/versions", body: body,
                  idempotency_key: idempotency_key)
        end

        # +GET /v1/policies/:id/versions/:versionId+ — one version, by id or label.
        def get(id_or_key, version_id_or_label)
          request(method: :get, path: version_path(id_or_key, version_id_or_label))
        end

        # +PATCH /v1/policies/:id/versions/:versionId+ — edit a draft (409 for a published version).
        def update(id_or_key, version_id_or_label, body, idempotency_key: nil)
          request(method: :patch, path: version_path(id_or_key, version_id_or_label), body: body,
                  idempotency_key: idempotency_key)
        end

        # +DELETE /v1/policies/:id/versions/:versionId+ — delete a draft (409 for a published version: retire it).
        def delete(id_or_key, version_id_or_label)
          request(method: :delete, path: version_path(id_or_key, version_id_or_label))
        end

        # +POST /v1/policies/:id/versions/:versionId/publish+ — publish a draft. +effective_at+ (epoch ms or ISO, default now)
        # is when sign-ups must accept it and sign-ins re-ask per the policy's +reaccept+ rule.
        def publish(id_or_key, version_id_or_label, body = {}, idempotency_key: nil)
          request(method: :post, path: "#{version_path(id_or_key, version_id_or_label)}/publish", body: body,
                  idempotency_key: idempotency_key)
        end

        # +POST /v1/policies/:id/versions/:versionId/retire+ — retire a published version; its acceptances stay.
        def retire(id_or_key, version_id_or_label, idempotency_key: nil)
          request(method: :post, path: "#{version_path(id_or_key, version_id_or_label)}/retire",
                  idempotency_key: idempotency_key)
        end

        private

        def version_path(id_or_key, version_id_or_label)
          "/v1/policies/#{enc(id_or_key)}/versions/#{enc(version_id_or_label)}"
        end
      end

      # +/v1/instance/policy_settings+.
      class Settings < Base
        # +GET /v1/instance/policy_settings+ — +{ session_claim }+.
        def get
          request(method: :get, path: "/v1/instance/policy_settings")
        end

        # +PATCH /v1/instance/policy_settings+ — turn the +pol+ session claim (the accepted version of each required policy) on or off.
        def update(body)
          request(method: :patch, path: "/v1/instance/policy_settings", body: body)
        end
      end
    end

    # +/v1/instance/policy_source+ — the external policy source (Atlas policy
    # source protocol v1): serve your policies from a CMS or your own service.
    # Atlas fetches +GET {endpoint_url}/policies+ signed with the source's
    # signing secret ({Atlas::PolicySourceProtocol.verify_feed_request} checks
    # it) and your source tells Atlas about changes with a signed event
    # ({Atlas::PolicySourceProtocol.sign_event}). +signing_secret+ is write-only.
    class PolicySource < Base
      # +GET /v1/instance/policy_source+ — endpoint, sync mode, the +webhook_url+ to give the source, the last sync outcome.
      def get
        request(method: :get, path: "/v1/instance/policy_source")
      end

      # +PUT /v1/instance/policy_source+ — configure the source; only the keys sent change, +nil+ clears.
      # Enabling needs +endpoint_url+ and +signing_secret+. +sync+ is +webhook+ or +poll+ (+poll_interval_minutes+ 5-1440).
      def update(body)
        request(method: :put, path: "/v1/instance/policy_source", body: body)
      end

      # +DELETE /v1/instance/policy_source+ — disconnect the source (its policies and history stay).
      def delete
        request(method: :delete, path: "/v1/instance/policy_source")
      end

      # +POST /v1/instance/policy_source/test+ — a signed fetch of the feed, validated but not stored.
      def test
        request(method: :post, path: "/v1/instance/policy_source/test")
      end

      # +POST /v1/instance/policy_source/sync+ — fetch the feed now and store it.
      def sync
        request(method: :post, path: "/v1/instance/policy_source/sync")
      end

      # +GET /v1/instance/policy_source/deliveries+ — the delivery log, newest first. +params+: +limit+, +starting_after+, +kind+, +status+.
      def list_deliveries(params = {})
        request(method: :get, path: "/v1/instance/policy_source/deliveries", query: params)
      end
    end
  end
end
