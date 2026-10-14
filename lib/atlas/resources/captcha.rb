# frozen_string_literal: true

require_relative "base"

module Atlas
  module Resources
    # +/v1/captcha+ — verify a CAPTCHA token server-side with the instance's configured provider.
    class Captcha < Base
      # +POST /v1/captcha/verify+ — verify a CAPTCHA token against the instance's configured provider. Fails closed.
      def verify(body)
        request(method: :post, path: "/v1/captcha/verify", body: body)
      end
    end
  end
end
