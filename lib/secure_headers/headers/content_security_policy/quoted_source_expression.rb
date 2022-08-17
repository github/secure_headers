# frozen_string_literal: true

module SecureHeaders
  class ContentSecurityPolicy
    # Keyword, nonce, or hash source
    class QuotedSourceExpression
      attr_reader :value

      def initialize(value:)
        @value = value
      end

      def to_str
        "#{value}"
      end

      def has_wildcard?
        false
      end

      # For now, we only return true for exact matches.
      def matches_same_or_superset?(other_source)
        return false unless other_source.is_a?(QuotedSourceExpression)
        @value == other_source.value
      end

      def self.parse(s)
        puts "--------"
        
        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        # Rather than validating against the spec, we are flexible here for now.
        value_match = s.match(/\A(?<value>'[[[:alpha:]][[:digit:]]\-\+_=]+')\z/)
        value = value_match[:value]
        
        new(
          value: value
        )
      end
    end
  end
end

kse = SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.parse("'self'")
kse = SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.parse("'-self'")
kse.to_str

kse = SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.parse("'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='")
kse = SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.parse("'nonce-abcdefg'")
kse.to_str
kse = SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.parse("'wasm-unsafe-eval'")
kse.to_str
