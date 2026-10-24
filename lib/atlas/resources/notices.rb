# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/instance/notices+ — platform notices for the instance owner.
    class Notices < Base
      # +all: true+ includes acknowledged notices.
      def list(params = {})
        request(method: :get, path: "/v1/instance/notices", query: params.empty? ? nil : params)
      end

      def acknowledge(id)
        request(method: :post, path: "/v1/instance/notices/#{enc(id)}/acknowledge")
      end
    end

    # +/v1/security_advisories+ — Atlas security advisories (for example ATLAS-SA-2026-001).
    class SecurityAdvisories < Base
      def list
        request(method: :get, path: "/v1/security_advisories")
      end

      def acknowledge(id)
        request(method: :post, path: "/v1/security_advisories/#{enc(id)}/acknowledge")
      end

      # +GET /v1/public/security_advisories+ — the public list (no key needed).
      def list_public
        request(method: :get, path: "/v1/public/security_advisories")
      end
    end

    # +/v1/audit_exports+ — forward the audit log to your SIEM. The signing secret is
    # revealed once (create, rotate_secret) and is write-only afterwards.
    class AuditExports < Base
      def list
        request(method: :get, path: "/v1/audit_exports")
      end

      def get(id)
        request(method: :get, path: "/v1/audit_exports/#{enc(id)}")
      end

      def create(body, idempotency_key: nil)
        request(method: :post, path: "/v1/audit_exports", body: body, idempotency_key: idempotency_key)
      end

      def update(id, body)
        request(method: :patch, path: "/v1/audit_exports/#{enc(id)}", body: body)
      end

      def delete(id)
        request(method: :delete, path: "/v1/audit_exports/#{enc(id)}")
      end

      def test(id)
        request(method: :post, path: "/v1/audit_exports/#{enc(id)}/test")
      end

      def rotate_secret(id)
        request(method: :post, path: "/v1/audit_exports/#{enc(id)}/rotate_secret")
      end
    end

    # +GET /v1/instance/sub_processors+ — Atlas's sub-processors for this instance.
    class SubProcessors < Base
      def list
        request(method: :get, path: "/v1/instance/sub_processors")
      end
    end
  end
end
