# frozen_string_literal: true

require_relative "integrations"

module Atlas
  module Resources
    class Integrations
      # Run a card action. revoke_sessions signs the user out of every device (their sessions end,
      # back-channel logouts go out) and is audited with the agent the integration names. Partner
      # link with sessions:write, or the secret key.
      # Scope: sessions:write. query: dry_run. body requires: sub.
      def run_card_action(integration, action, body, query = nil, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/integrations/#{enc(integration)}/card/actions/#{enc(action)}",
          query: query,
          body: body,
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
