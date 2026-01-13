# frozen_string_literal: true
module SecureHeaders
  class ReportingEndpointsConfigError < StandardError; end
  class ReportingEndpoints
    HEADER_NAME = "reporting-endpoints".freeze

    class << self
      # Public: generate a Reporting-Endpoints header.
      #
      # The config should be a Hash of endpoint names to URLs.
      # Example: { "csp-endpoint" => "https://example.com/reports" }
      #
      # Returns nil if config is OPT_OUT or nil, or a header name and
      # formatted header value based on the config.
      def make_header(config = nil)
        return if config.nil? || config == OPT_OUT
        validate_config!(config)
        [HEADER_NAME, format_endpoints(config)]
      end

      def validate_config!(config)
        case config
        when nil, OPT_OUT
          # valid
        when Hash
          config.each_pair do |name, url|
            if name.is_a?(Symbol)
              name = name.to_s
            end
            unless name.is_a?(String) && !name.empty?
              raise ReportingEndpointsConfigError.new("Endpoint name must be a non-empty string, got: #{name.inspect}")
            end
            unless url.is_a?(String) && !url.empty?
              raise ReportingEndpointsConfigError.new("Endpoint URL must be a non-empty string, got: #{url.inspect}")
            end
            unless url.start_with?("https://")
              raise ReportingEndpointsConfigError.new("Endpoint URLs must use https, got: #{url.inspect}")
            end
          end
        else
          raise TypeError.new("Must be a Hash of endpoint names to URLs. Found #{config.class}: #{config}")
        end
      end

      private

      def format_endpoints(config)
        config.map do |name, url|
          %{#{name}="#{url}"}
        end.join(", ")
      end
    end
  end
end
