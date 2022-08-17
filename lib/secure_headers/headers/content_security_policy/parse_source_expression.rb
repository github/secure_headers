# frozen_string_literal: true

require_relative "host_source_expression"
require_relative "path_reporting_endpoint"
require_relative "quoted_source_expression"
require_relative "scheme_source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    def parse_source_expression(s)
      SecureHeaders::ContentSecurityPolicy::QuotedSourceExpression.try_parse(s) ||
        SecureHeaders::ContentSecurityPolicy::SchemeSourceExpression.try_parse(s) ||
        SecureHeaders::ContentSecurityPolicy::PathReportingEndpoint.try_parse(s) ||
        # TODO: bare directive like `style-src` are parsed as hosts. They should be handled separately.
        SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse(s)
    end
  end
end

# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("url-aldkjfl://*")
# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("aa.df://r")
# s = SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("*")
# s.to_s
# nSecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("url-aldkjf")
# s = SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("http://localhost:3434/fsd")
# puts "\n\ns: #{s.to_s}\n\n"
# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("https://w3c.github.io/webappsec-csp/#grammardef-scheme-part")
