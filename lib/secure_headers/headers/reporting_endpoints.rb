# frozen_string_literal: true
module SecureHeaders
  class ReportingEndpointsConfigError < StandardError; end

  class ReportingEndpoints
    HEADER_NAME = "reporting-endpoints".freeze
    INVALID_CONFIGURATION_ERROR = "config must be a hash.".freeze
    INVALID_ENDPOINT_NAME_ERROR = "endpoint names must be strings or symbols.".freeze
    INVALID_ENDPOINT_URL_ERROR = "endpoint URLs must be strings.".freeze

    # Public: Generate a Reporting-Endpoints header.
    #
    # Returns nil if not configured, returns header name and value if
    # configured.
    def self.make_header(config, user_agent = nil)
      return if config.nil? || config == OPT_OUT

      header = new(config)
      [HEADER_NAME, header.value]
    end

    def self.validate_config!(config)
      return if config.nil? || config == OPT_OUT
      raise ReportingEndpointsConfigError.new(INVALID_CONFIGURATION_ERROR) unless config.is_a?(Hash)

      config.each do |name, url|
        unless name.is_a?(String) || name.is_a?(Symbol)
          raise ReportingEndpointsConfigError.new(INVALID_ENDPOINT_NAME_ERROR)
        end

        unless url.is_a?(String)
          raise ReportingEndpointsConfigError.new(INVALID_ENDPOINT_URL_ERROR)
        end
      end
    end

    def initialize(config)
      @endpoints = config
    end

    def value
      @endpoints.map { |name, url| "#{name}=\"#{url}\"" }.join(", ")
    end
  end
end
