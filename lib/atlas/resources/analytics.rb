# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    class Analytics < Base
      # Where sign-in or sign-up attempts end, per method: started, completed, abandoned, and the
      # step each unfinished attempt stopped at, with the completion rate. Each attempt is counted
      # once, at its final state.
      # Scope: analytics:read. query: kind, from, to, days, granularity, organization_id, format,
      # limit, starting_after.
      def funnel(query = nil)
        request(method: :get, path: "/v1/analytics/funnel", query: query)
      end

      # What happened at each step of a sign-in journey: how often it held a sign-in (a required
      # action or form), was completed, ran at the sign-in (an Action, claim or redirect) or refused
      # it, with the completion rate of its holds. Steps follow the active version; a sub-flow's
      # steps are prefixed with the sub-flow step id. No organization slice.
      # Scope: analytics:read. query: journey_id (required), from, to, days, granularity,
      # organization_id, format, limit, starting_after.
      def journey_funnel(query = nil)
        request(method: :get, path: "/v1/analytics/journey_funnel", query: query)
      end

      # Failed first- and second-factor attempts by reason and method, most frequent first. No
      # organization slice (a failed attempt belongs to no organization).
      # Scope: analytics:read. query: from, to, days, granularity, organization_id, format, limit,
      # starting_after.
      def failures(query = nil)
        request(method: :get, path: "/v1/analytics/failures", query: query)
      end

      # Sign-ins split by one dimension: method, device type, browser, operating system or country
      # (country needs a GeoIP database on the deployment; otherwise it reports +unknown+).
      # Scope: analytics:read. query: dimension, from, to, days, granularity, organization_id,
      # format, limit, starting_after.
      def breakdown(query = nil)
        request(method: :get, path: "/v1/analytics/breakdown", query: query)
      end

      # Distinct active users and sign-ins per bucket, each bucket split into new users (signed up
      # in that bucket) and returning users, plus trailing 1/7/30-day active-user counts (dau, wau,
      # mau) ending at +to+.
      # Scope: analytics:read. query: from, to, days, granularity, organization_id, format, limit,
      # starting_after.
      def active_users(query = nil)
        request(method: :get, path: "/v1/analytics/active_users", query: query)
      end

      # How many users hold a passkey (adoption rate), and the passkey share of sign-ins per bucket.
      # Scope: analytics:read. query: from, to, days, granularity, organization_id, format, limit,
      # starting_after.
      def passkey_adoption(query = nil)
        request(method: :get, path: "/v1/analytics/passkey_adoption", query: query)
      end

      # API usage per subject against its own baseline: secret keys calling the Backend API,
      # end-user API keys verified through /v1/api_keys/verify, and organizations (Backend API calls
      # on the organization plus verifications of its keys). For each: requests and the failure rate
      # in the window, the average hourly rate over the 7 days before, and the ratio between them,
      # highest ratio first (at most 100). Counts are written in batches and can lag by up to a
      # minute.
      # Scope: analytics:read. query: subject_type, subject_id, window_minutes, limit,
      # starting_after.
      def api_usage(query = nil)
        request(method: :get, path: "/v1/analytics/api_usage", query: query)
      end

      def reports
        @reports ||= Reports.new(@transport)
      end

      def alert_rules
        @alert_rules ||= AlertRules.new(@transport)
      end

      class Reports < Base
        # Compliance report: users who have not signed in for +inactive_days+ (default 90), oldest
        # id first, cursor-paginated (an export returns up to 50,000 rows).
        # Scope: analytics:read. query: inactive_days, limit, starting_after, from, to, days,
        # granularity, organization_id, format.
        def inactive_users(query = nil)
          request(method: :get, path: "/v1/analytics/reports/inactive_users", query: query)
        end

        # Compliance report: how many users are protected by a second factor, a passkey, either, or
        # neither.
        # Scope: analytics:read. query: from, to, days, granularity, organization_id, format, limit,
        # starting_after.
        def mfa_coverage(query = nil)
          request(method: :get, path: "/v1/analytics/reports/mfa_coverage", query: query)
        end

        # Compliance report: for each application (OAuth client), how many users have access, how
        # many grants are active and how many users signed in during the window.
        # Scope: analytics:read. query: from, to, days, granularity, organization_id, format, limit,
        # starting_after.
        def access_by_app(query = nil)
          request(method: :get, path: "/v1/analytics/reports/access_by_app", query: query)
        end
      end

      class AlertRules < Base
        # List analytics alert rules with their state and last measured value. The metric catalog is
        # included.
        # Scope: analytics:read. query: limit, starting_after.
        def list(query = nil)
          request(method: :get, path: "/v1/analytics/alert_rules", query: query)
        end

        # Create an alert rule: tell me when a sign-in health metric, or a key or organization's API
        # usage against its baseline, crosses a threshold over a trailing window. It must have
        # email_contacts, a webhook_url or ssf. A webhook signing secret is returned once.
        # Scope: analytics:write. query: dry_run. body requires: name, metric, comparator,
        # threshold.
        def create(body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/analytics/alert_rules",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # One analytics alert rule.
        # Scope: analytics:read.
        def get(id)
          request(method: :get, path: "/v1/analytics/alert_rules/#{enc(id)}")
        end

        # Edit an alert rule. Editing re-arms it.
        # Scope: analytics:write. query: dry_run.
        def update(id, body, query = nil, idempotency_key: nil)
          request(
            method: :patch,
            path: "/v1/analytics/alert_rules/#{enc(id)}",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end

        # Delete an alert rule.
        # Scope: analytics:write. query: dry_run.
        def delete(id, query = nil, idempotency_key: nil)
          request(
            method: :delete,
            path: "/v1/analytics/alert_rules/#{enc(id)}",
            query: query,
            idempotency_key: idempotency_key
          )
        end

        # Measure the rule now. With +notify: true+ it also sends the rule's email and webhook,
        # whether or not the rule is breaching, to prove the delivery path.
        # Scope: analytics:write. query: dry_run.
        def test(id, body, query = nil, idempotency_key: nil)
          request(
            method: :post,
            path: "/v1/analytics/alert_rules/#{enc(id)}/test",
            query: query,
            body: body,
            idempotency_key: idempotency_key
          )
        end
      end
    end
  end
end
