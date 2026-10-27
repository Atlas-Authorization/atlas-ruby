# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class PolicyBundles < Base
      # The bundle revision the instance policy is at right now. Compare it with a deployed bundle’s
      # revision to detect drift.
      # Scope: policy_bundles:read.
      def current
        request(method: :get, path: "/v1/policy_bundles/current")
      end

      # List the signed policy bundles exported or imported on this instance, newest first (without
      # the archives).
      # Scope: policy_bundles:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/policy_bundles", query: query)
      end

      # Export the instance policy — every ABAC policy (current version), the ABAC entity schema,
      # templates and template links, and every FGA store’s latest authorization model — as a
      # versioned tar.gz with a manifest of file digests, signed with the instance signing key
      # (detached JWS). The same policy always has the same revision.
      # Scope: policy_bundles:write. query: dry_run.
      def export(query = nil, idempotency_key: nil)
        request(method: :post, path: "/v1/policy_bundles", query: query, idempotency_key: idempotency_key)
      end

      # Read a stored bundle by revision, with the base64 archive and its signature.
      # Scope: policy_bundles:read.
      def get(revision)
        request(method: :get, path: "/v1/policy_bundles/#{enc(revision)}")
      end

      # Download a stored bundle as the raw tar.gz (+application/gzip+). The detached signature is
      # in the +Atlas-Bundle-Signature+ header, with +Atlas-Bundle-Revision+ and
      # +Atlas-Bundle-Key-Id+.
      # Scope: policy_bundles:read. Returns the raw application/gzip body as a String.
      def archive(revision)
        request(method: :get, path: "/v1/policy_bundles/#{enc(revision)}/archive", raw: true)
      end

      # Check a bundle without importing it: the detached signature against this instance's signing
      # keys (plus any +trusted_jwks+ you supply) and the archive's integrity. The SDK can do the
      # same check offline.
      # Scope: policy_bundles:read. query: dry_run. body requires: bundle, signature.
      def verify(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/policy_bundles/verify",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Import a signed bundle. The signature and the archive integrity must both check out or
      # nothing is touched (422). With +dry_run: true+ it returns the diff of what would change and
      # applies nothing (needs only policy_bundles:read). Otherwise it applies everything in one
      # transaction: stores and models first, then the ABAC schema, templates, links and policies; a
      # changed policy appends a version. +prune+ also deletes ABAC policies, templates and links
      # the bundle does not name (and the schema when it has none); FGA stores are never deleted.
      # Scope: policy_bundles:write. query: dry_run. body requires: bundle, signature.
      def import(body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/policy_bundles/import",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
