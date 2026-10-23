# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/better_auth_imports+ — migrate from Better Auth: import a sealed bundle
    # made by the Better Auth exporter (+npx atlas-better-auth-export+).
    #
    #   1. +get_public_key+ — the key the exporter seals the bundle to.
    #   2. +upload+ (or +create+, +upload_part+ per part and +finalize+) — Atlas
    #      opens the bundle and runs the dry run.
    #   3. Read the import's +report+, then +apply+. Applying again after a
    #      failure resumes where it stopped; every record is an idempotent upsert.
    #
    # Statuses: uploading → analyzing → ready | invalid → queued → applying →
    # completed | failed.
    class BetterAuthImports < Base
      # Bytes per uploaded part (the API takes at most 10 MiB per part).
      PART_BYTES = 8 * 1024 * 1024
      # Statuses an import stays in while Atlas works on it (+wait_for+ polls through them).
      IN_FLIGHT = %w[analyzing queued applying].freeze

      # Split a sealed bundle into upload parts of at most +max_bytes+, each
      # ending on a line boundary. Empty lines are dropped; a single line longer
      # than +max_bytes+ becomes a part of its own.
      # @return [Array<String>]
      def self.split_bundle_parts(bundle, max_bytes = PART_BYTES)
        raise ArgumentError, "max_bytes must be positive" unless max_bytes.to_i.positive?

        parts = []
        current = +""
        bundle.to_s.b.split("\n").each do |line|
          line = line.chomp("\r")
          next if line.empty?

          if !current.empty? && current.bytesize + line.bytesize + 1 > max_bytes
            parts << current
            current = +""
          end
          current << line << "\n"
        end
        parts << current unless current.empty?
        parts.map { |p| p.force_encoding(Encoding::UTF_8) }
      end

      # +GET /v1/better_auth_imports/public_key+ — the import key (created on first read).
      def get_public_key
        request(method: :get, path: "/v1/better_auth_imports/public_key")
      end

      # +POST /v1/better_auth_imports/public_key/rotate+ — replace the import key;
      # bundles sealed to the old one no longer finalize (+import_key_retired+).
      def rotate_public_key(idempotency_key: nil)
        request(method: :post, path: "/v1/better_auth_imports/public_key/rotate", idempotency_key: idempotency_key)
      end

      # +POST /v1/better_auth_imports+ — start an import (status +uploading+); +{ options: }+ optional.
      def create(body = {}, idempotency_key: nil)
        request(method: :post, path: "/v1/better_auth_imports", body: body || {}, idempotency_key: idempotency_key)
      end

      # +GET /v1/better_auth_imports+ — imports, newest first (+limit+, +starting_after+).
      def list(params = nil)
        request(method: :get, path: "/v1/better_auth_imports", query: params)
      end

      # +GET /v1/better_auth_imports/:id+ — status, progress, the dry-run +report+ and the +result+.
      def get(id)
        request(method: :get, path: "/v1/better_auth_imports/#{enc(id)}")
      end

      # +PUT /v1/better_auth_imports/:id/parts/:part+ — upload part +part+ (1-based)
      # of the sealed bundle: whole lines, at most 10 MiB, sent as text/plain.
      # Re-sending a part replaces it.
      def upload_part(id, part, data)
        request(method: :put, path: "/v1/better_auth_imports/#{enc(id)}/parts/#{Integer(part)}",
                raw_body: data.to_s, content_type: "text/plain; charset=utf-8")
      end

      # +POST /v1/better_auth_imports/:id/finalize+ — close the upload; Atlas checks
      # the parts and the key and runs the dry run (inline up to 4 MiB, otherwise
      # +analyzing+ in the background).
      def finalize(id)
        request(method: :post, path: "/v1/better_auth_imports/#{enc(id)}/finalize")
      end

      # +POST /v1/better_auth_imports/:id/dry_run+ — run the dry run again; new +options+ replace the stored ones.
      def dry_run(id, body = {})
        request(method: :post, path: "/v1/better_auth_imports/#{enc(id)}/dry_run", body: body || {})
      end

      # +POST /v1/better_auth_imports/:id/apply+ — import (or resume a failed import
      # from its cursor). Pass +{ confirm_conflicts: true }+ when the dry run reported conflicts.
      def apply(id, body = {})
        request(method: :post, path: "/v1/better_auth_imports/#{enc(id)}/apply", body: body || {})
      end

      # +DELETE /v1/better_auth_imports/:id+ — remove the import and its stored bundle; imported data stays.
      def delete(id)
        request(method: :delete, path: "/v1/better_auth_imports/#{enc(id)}")
      end

      # +GET /v1/better_auth_imports/jwks+ — the Better Auth JWT keys published in the instance JWKS for the cutover.
      def list_jwks
        request(method: :get, path: "/v1/better_auth_imports/jwks")
      end

      # +DELETE /v1/better_auth_imports/jwks/:kid+ — stop publishing one imported key.
      def delete_jwk(kid)
        request(method: :delete, path: "/v1/better_auth_imports/jwks/#{enc(kid)}")
      end

      # Create an import, upload the sealed bundle in line-aligned parts of at
      # most +part_bytes+ and finalize it. Yields +(n, of)+ after each part.
      # @return [Hash] the finalized import (+ready+ / +invalid+, or +analyzing+ — see {#wait_for}).
      def upload(bundle, options: nil, part_bytes: PART_BYTES)
        parts = self.class.split_bundle_parts(bundle, part_bytes)
        raise ArgumentError, "The bundle is empty." if parts.empty?

        created = create(options ? { options: options } : {})
        id = created.is_a?(Hash) ? created["id"] : nil
        raise Atlas::Error, "Atlas did not return an import id." if id.nil? || id.to_s.empty?

        parts.each_with_index do |part, i|
          upload_part(id, i + 1, part)
          yield(i + 1, parts.length) if block_given?
        end
        finalize(id)
      end

      # Poll until the import leaves +analyzing+ / +queued+ / +applying+ and
      # return it. Yields each polled import. Raises {Atlas::Error} after +timeout+ seconds.
      def wait_for(id, interval: 2.0, timeout: 6 * 3600.0, sleeper: ->(s) { sleep(s) })
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          imp = get(id)
          yield(imp) if block_given?
          return imp unless IN_FLIGHT.include?(imp.is_a?(Hash) ? imp["status"] : nil)

          if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
            raise Atlas::Error, "Timed out waiting for Better Auth import #{id} (status #{imp['status']})."
          end

          sleeper.call(interval)
        end
      end
    end
  end
end
