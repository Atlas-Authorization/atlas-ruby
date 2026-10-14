# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/email_addresses+ — act on an email address by its own id.
    class EmailAddresses < Base
      # +POST /v1/email_addresses/:eid/verify+ — mark an email address verified (the owning user is derived from the address).
      def verify(email_address_id, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/email_addresses/#{enc(email_address_id)}/verify",
          idempotency_key: idempotency_key
        )
      end

      # +POST /v1/email_addresses/:eid/primary+ — make a verified email address its user's primary address.
      def set_primary(email_address_id, idempotency_key: nil)
        request(
          method: :post,
          path: "/v1/email_addresses/#{enc(email_address_id)}/primary",
          idempotency_key: idempotency_key
        )
      end
    end
  end
end
