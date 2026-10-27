# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class NetworkZones < Base
      # List reusable network zones — named sets of CIDRs, countries, ASNs and anonymizer classes
      # (tor, datacenter, vpn) that network ACL rules reference by zone_id.
      # Scope: network_acls:read. query: limit, starting_after.
      def list(query = nil)
        request(method: :get, path: "/v1/network_zones", query: query)
      end

      # Create a network zone. +name+ is unique per instance; +cidrs+, +countries+ (ISO alpha-2),
      # +asns+ and +anonymizers+ are unioned (any match = in the zone). Malformed entries are
      # refused.
      # Scope: network_acls:write. query: dry_run.
      def create(body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/network_zones",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Read one network zone.
      # Scope: network_acls:read.
      def get(id)
        request(method: :get, path: "/v1/network_zones/#{enc(id)}")
      end

      # Update a network zone. Sending any of cidrs/countries/asns/anonymizers replaces that list;
      # omitted lists keep their value.
      # Scope: network_acls:write. query: dry_run.
      def update(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :patch,
          path: "/v1/network_zones/#{enc(id)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end

      # Delete a network zone. The network ACL rules that reference it are deleted with it.
      # Scope: network_acls:write. query: dry_run.
      def delete(id, query = nil, idempotency_key: nil)
        request(
          method: :delete,
          path: "/v1/network_zones/#{enc(id)}",
          query: query,
          idempotency_key: idempotency_key
        )
      end

      # What-if: does an IP address fall inside this zone? Returns the resolved country / ASN / Tor
      # / datacenter facts alongside the answer. Facts the instance has no IP-intelligence data for
      # are null and never match.
      # Scope: network_acls:read. query: dry_run.
      def check(id, body = Atlas::Transport::OMIT, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/network_zones/#{enc(id)}/check",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
