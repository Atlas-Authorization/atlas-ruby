# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "atlas"

module Atlas
  module Test
    # A no-network requester matching the Transport +http:+ seam: responds to
    # +call(method, url, headers, body)+ and returns +[status, text]+.
    #
    # Each request is recorded (for assertions on method/url/headers/body) and
    # answered from a FIFO queue of canned responses.
    class StubRequester
      Request  = Struct.new(:method, :url, :headers, :body, keyword_init: true)
      Response = Struct.new(:status, :text, keyword_init: true)

      attr_reader :requests

      def initialize
        @requests  = []
        @responses = []
      end

      # Queue a response. +body+ may be a Hash/Array (JSON-encoded) or a String.
      def enqueue(status: 200, body: nil)
        text = body.nil? ? "" : (body.is_a?(String) ? body : JSON.generate(body))
        @responses << Response.new(status: status, text: text)
        self
      end

      # The last request made — convenience for single-call tests.
      def last = @requests.last

      def call(method, url, headers, body)
        @requests << Request.new(method: method, url: url, headers: headers, body: body)
        response = @responses.shift
        raise "StubRequester: no queued response for #{method} #{url}" if response.nil?

        [response.status, response.text]
      end
    end
  end
end
