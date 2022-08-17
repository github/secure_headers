# frozen_string_literal: true

module SecureHeaders
  class ContentSecurityPolicy
    # TODO: A reporting endpoint is not a source expression, but we don't make
    # that distinction in the rest of our code yet.
    class PathReportingEndpoint
      attr_reader :endpoint

      def initialize(scheme:)
        @endpoint = endpoint
      end

      def to_s
        @endpoint
      end

      def has_wildcard?
        false
      end

      def matches_same_or_superset?(other_source)
        false
      end

      def self.try_parse(s)
        endpoint_match = s.match(/\A(?<endpoint>\/.*)\z/)
        return nil if endpoint_match.nil?
        endpoint = endpoint_match[:scheme]
        new(
          endpoint: endpoint
        )
      end

      def self.parse(s)
        maybe_parsed = self.try_parse(s)
        throw "Could not parse path reporting endpoint" if maybe_parsed.nil?
        maybe_parsed
      end
    end
  end
end
