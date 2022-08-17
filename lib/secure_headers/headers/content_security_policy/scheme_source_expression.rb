# frozen_string_literal: true

require_relative "source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    class SchemeSourceExpression < SourceExpression
      attr_reader :scheme

      def initialize(scheme:)
        @scheme = scheme
      end

      def to_s
        @scheme + ":"
      end

      def matches_same_or_superset?(other_source)
        return false unless other_source.is_a?(SchemeSourceExpression)
        @scheme == other_source.scheme
      end

      def self.try_parse(s)
        scheme_match = s.match(/\A((?<scheme>[[:alpha:]][[[:alpha:]][[:digit:]]\+\-\.]*):)\z/)
        return nil if scheme_match.nil?
        scheme = scheme_match[:scheme]
        new(
          scheme: scheme
        )
      end
    end
  end
end
