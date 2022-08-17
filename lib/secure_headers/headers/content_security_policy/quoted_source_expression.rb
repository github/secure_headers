# frozen_string_literal: true

require_relative "source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    # Keyword, nonce, or hash source
    class QuotedSourceExpression < SourceExpression
      attr_reader :value

      def initialize(value:)
        @value = value
      end

      def to_s
        "#{value}"
      end

      # For now, we only return true for exact matches.
      def matches_same_or_superset?(other_source)
        return false unless other_source.is_a?(QuotedSourceExpression)
        @value == other_source.value
      end

      def self.try_parse(s)
        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        # Rather than validating against the spec, we are flexible here for now.
        value_match = s.match(/\A(?<value>'[[[:alpha:]][[:digit:]]\+\/\-_=]+')\z/)
        return nil if value_match.nil?
        value = value_match[:value]
        new(
          value: value
        )
      end
    end
  end
end
