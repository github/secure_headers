# frozen_string_literal: true

require_relative "source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    # TODO: A reporting endpoint is not a source expression, but we don't make
    # that distinction in the rest of our code yet. We need to make the rest of
    # the code parse closer to spec, and then we can remove this subclass.
    class PathReportingEndpoint < SourceExpression
      attr_reader :endpoint

      def initialize(endpoint:)
        @endpoint = endpoint
      end

      def to_s
        @endpoint
      end

      def self.try_parse(s)
        endpoint_match = s.match(/\A(?<endpoint>\/[^;,\n]*)\z/)
        return nil if endpoint_match.nil?
        endpoint = endpoint_match[:endpoint]
        new(
          endpoint: endpoint
        )
      end
    end
  end
end
