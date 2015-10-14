module SecureHeaders
  class STSConfigError < StandardError; end

  class StrictTransportSecurity < Header
    HEADER_NAME = 'Strict-Transport-Security'
    HSTS_MAX_AGE = "631138519"
    DEFAULT_VALUE = "max-age=" + HSTS_MAX_AGE
    VALID_STS_HEADER = /\Amax-age=\d+(; includeSubdomains)?(; preload)?\z/i
    MESSAGE = "The config value supplied for the HSTS header was invalid. Must match #{VALID_STS_HEADER}"
    CONFIG_KEY = :hsts

    class << self
      def make_header(config = nil)
        validate_config!(config) if validate_config?
        [HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config} #{config.class}") unless config.is_a?(String)
        raise STSConfigError.new(MESSAGE) unless config =~ VALID_STS_HEADER
      end
    end
  end
end
