# frozen_string_literal: true
module SecureHeaders
  class ReportingEndpointsConfigError < StandardError; end
  class ReportingEndpoints
    HEADER_NAME = "Reporting-Endpoints".freeze

    class << self
      # Public: generate an Reporting-Endpoints header.
      #
      # Returns nil if not configured or opted out, returns an empty string if configuration
      # is empty, returns header name and value if configured.
      def make_header(config = nil, user_agent = nil)
        case config
        when nil, OPT_OUT
          # noop
        when Hash
          [HEADER_NAME, make_header_value(config)]
        end
      end

      def validate_config!(config)
        case config
        when nil, OPT_OUT, {}
          # valid
        when Hash
          unless config.values.all? { |endpoint| endpoint.is_a?(String) }
            raise ReportingEndpointsConfigError.new("endpoints must be Strings")
          end
        else
          raise ReportingEndpointsConfigError.new("config must be a Hash")
        end
      end

      def make_header_value(endpoints)
        endpoints.map { |name, endpoint| "#{name}=\"#{endpoint}\"" }.join(",")
      end
    end
  end
end
