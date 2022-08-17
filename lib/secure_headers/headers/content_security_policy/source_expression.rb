# frozen_string_literal: true

require_relative "host_source_expression"
require_relative "quoted_source_expression"
require_relative "scheme_source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    def parse_source_expression(s)
      SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.try_parse(s) ||
        SecureHeaders::ContentSecurityPolicy::SchemeSourceExpression.try_parse(s) ||
        SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse(s)
    end
  end
end

# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("url-aldkjfl://*")
# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("aa.df://r")
# s = SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("*")
# s.to_str
# nSecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("url-aldkjf")
# s = SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("http://localhost:3434/fsd")
# puts "\n\ns: #{s.to_str}\n\n"
# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("https://w3c.github.io/webappsec-csp/#grammardef-scheme-part")
