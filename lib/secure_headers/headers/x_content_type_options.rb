# frozen_string_literal: true
module SecureHeaders
  class XContentTypeOptionsConfigError < StandardError; end

  class XContentTypeOptions
    HEADER_NAME = "x-content-type-options".freeze
    DEFAULT_VALUE = "nosniff"

    # Public: generate an X-Content-Type-Options header.
    #
    # Returns a default header if no configuration is provided, or a
    # header name and value based on the config.
    def self.make_header(config = nil, user_agent = nil)
      return if config == OPT_OUT
      [HEADER_NAME, config || DEFAULT_VALUE]
    end

    def self.validate_config!(config)
      return if config.nil? || config == OPT_OUT
      raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
      unless config.casecmp(DEFAULT_VALUE) == 0
        raise XContentTypeOptionsConfigError.new("Value can only be nil or 'nosniff'")
      end
    end
  end
end
