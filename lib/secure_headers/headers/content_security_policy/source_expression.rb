# frozen_string_literal: true

module SecureHeaders
  class ContentSecurityPolicy
    class SourceExpression
      def initialize(scheme:)
        throw "Cannot instantiate directly"
      end

      def to_s
        throw "Unimplemented"
      end

      def has_wildcard?
        false
      end

      def matches_same_or_superset?(other_source)
        false
      end

      def self.try_parse(s)
        throw "Unimplemented"
      end

      def self.parse(s)
        maybe_parsed = self.try_parse(s)
        throw "Could not parse scheme source expression" if maybe_parsed.nil?
        maybe_parsed
      end
    end
  end
end
