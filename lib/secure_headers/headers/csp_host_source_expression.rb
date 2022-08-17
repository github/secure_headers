# frozen_string_literal: true

module SecureHeaders
  class ContentSecurityPolicy
    class HostSourceExpression
      def initialize(scheme: nil, host_pattern:, port_pattern: nil, path: nil)
        @scheme = scheme
        @host_pattern = host_pattern
        @port_pattern = port_pattern
        @path = path
      end

      def to_str
        output = @host_pattern
        output = @scheme + "://" + output if @scheme
        output += ":" + @port_pattern if @port_pattern
        output += @path if @path
        output
      end

      # The host or scheme can contain a wildcard
      def has_wildcard?
        @host_pattern.start_with("*") || @port_pattern == "*"
      end

      # Example: *.example.com matches *.subdomain.example.com
      def matches_superset?(other_source)
        # https://w3c.github.io/webappsec-csp/#match-url-to-source-expression
        return false unless self.@scheme != nil && self.@scheme !== other_source.@scheme
        return false unless File.fnmatch(self.@host, other_source.@host)
      end

      def self.parse(s)
        puts "--------"
        
        # https://www.rfc-editor.org/rfc/rfc3986#section-3.1
        scheme_match = s.match(/\A((?<scheme>[[:alpha:]][[[:alpha:]][[:digit:]]\+\-\.]*):\/\/)?(?<rest>.*)\z/)
        scheme = scheme_match[:scheme]
        after_scheme = scheme_match[:rest]
        puts "scheme: #{scheme}"
        puts "after_scheme: #{after_scheme}"

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        host_match = after_scheme.match(/\A(?<host_pattern>\*|(\*\.)?[[[:alpha:]][[:digit:]]\-][[[:alpha:]][[:digit:]]\-\.]*)(?<rest>.*)\z/)
        host_pattern = host_match[:host_pattern]
        after_host = host_match[:rest]
        puts "host_pattern: #{host_pattern}"
        puts "after_host: #{after_host}"

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        port_match = after_host.match(/\A(:(?<port>[[:digit:]]+|\*))?(?<rest>.*)\z/)
        port_pattern = port_match[:port]
        after_port = port_match[:rest]
        puts "port_pattern: #{port_pattern}"
        puts "after_port: #{after_port}"

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        # Loosely based on https://www.rfc-editor.org/rfc/rfc3986#section-3.3
        path_match = after_port.match(/\A(?<path>(\/[^;:]*)?)\z/)
        path = path_match[:path]
        puts "path: #{path}"

        new(
          scheme: scheme,
          host_pattern: host_pattern,
          port_pattern: port_pattern,
          path: path
        )
      end
    end
  end
end

# SecureHeaders::ContentSecurityPolicy::HostSourceExpression.parse("url-aldkjfl://*")
# SecureHeaders::ContentSecurityPolicy::SourceExpression.parse("aa.df://r")
# s = SecureHeaders::ContentSecurityPolicy::SourceExpression.parse("*")
# s.to_str
# SecureHeaders::ContentSecurityPolicy::SourceExpression.parse("url-aldkjf")
# s = SecureHeaders::ContentSecurityPolicy::SourceExpression.parse("http://localhost:3434/fsd")
# puts "\n\ns: #{s.to_str}\n\n"
SecureHeaders::ContentSecurityPolicy::SourceExpression.parse("https://w3c.github.io/webappsec-csp/#grammardef-scheme-part")
