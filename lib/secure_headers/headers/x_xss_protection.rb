module SecureHeaders
  class XXssProtectionConfigError < StandardError; end
  class XXssProtection < Header
    HEADER_NAME = 'X-XSS-Protection'
    DEFAULT_VALUE = "1"
    VALID_X_XSS_HEADER = /\A[01](; mode=block)?(; report=.*)?\z/i
    CONFIG_KEY = :x_xss_protection

    class << self
      def make_header(config = nil)
        validate_config!(config) if validate_config?
        [HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        raise XXssProtectionConfigError.new("Invalid format (see VALID_X_XSS_HEADER)") unless config.to_s =~ VALID_X_XSS_HEADER
      end
    end
  end
end
