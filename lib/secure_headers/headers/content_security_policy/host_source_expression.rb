# frozen_string_literal: true

require_relative "source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    class HostSourceExpression < SourceExpression
      attr_reader :scheme, :host_pattern, :port_pattern, :path

      def initialize(scheme: nil, host_pattern: "", port_pattern: nil, path: nil)
        @scheme = scheme
        @host_pattern = host_pattern
        @port_pattern = port_pattern
        @path = path
      end

      def to_s
        output = @host_pattern
        output = @scheme + "://" + output if @scheme
        output += ":" + @port_pattern if @port_pattern
        output += @path if @path
        output
      end

      # The host or scheme can contain a wildcard
      def has_wildcard?
        @host_pattern.start_with?("*") || @port_pattern == "*"
      end

      # Example: *.example.com matches *.subdomain.example.com
      def matches_same_or_superset?(other_source)
        return false unless other_source.is_a?(HostSourceExpression)
        # A pared-down version of https://w3c.github.io/webappsec-csp/#match-url-to-source-expression
        # It's:
        # - okay to have some false negatives (i.e. incorrectly return `false`), since this is only used to optimize deduplication,
        # - as long as we don't have false positives (i.e. incorrectly return `true`).
        return false unless @scheme == other_source.scheme
        return false unless File.fnmatch(@host_pattern, other_source.host_pattern)
        return false unless @port_pattern == "*" || @port_pattern == other_source.port_pattern
        # Based on https://w3c.github.io/webappsec-csp/#path-part-match without percent-decoding.
        pathA = @path
        pathB = other_source.path
        pathA += "/" unless pathA.end_with?("/")
        pathB += "/" unless pathB.end_with?("/")
        pathB.start_with?(pathA)
      end

      def self.try_parse(s)
        # https://www.rfc-editor.org/rfc/rfc3986#section-3.1
        scheme_match = s.match(/\A((?<scheme>[[:alpha:]][[[:alpha:]][[:digit:]]\+\-\.]*):\/\/)?(?<rest>.*)\z/)
        return nil if scheme_match.nil?
        scheme = scheme_match[:scheme]
        after_scheme = scheme_match[:rest]

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        host_match = after_scheme.match(/\A(?<host_pattern>(\*\.)?[[[:alpha:]][[:digit:]]\-][[[:alpha:]][[:digit:]]\-\.]*|\*)(?<rest>.*)\z/)
        return nil if host_match.nil?
        host_pattern = host_match[:host_pattern]
        after_host = host_match[:rest]

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        port_match = after_host.match(/\A(:(?<port>[[:digit:]]+|\*))?(?<rest>.*)\z/)
        return nil if port_match.nil?
        port_pattern = port_match[:port]
        after_port = port_match[:rest]

        # https://w3c.github.io/webappsec-csp/#grammardef-scheme-part
        # Loosely based on https://www.rfc-editor.org/rfc/rfc3986#section-3.3
        path_match = after_port.match(/\A(?<path>(\/[^;,\n]*)?)\z/)
        return nil if path_match.nil?
        path = path_match[:path]

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
