module SecureHeaders
  class STSConfigError < StandardError; end

  class StrictTransportSecurity < Header
    module Constants
      HSTS_HEADER_NAME = 'Strict-Transport-Security'
      HSTS_MAX_AGE = "631138519"
      DEFAULT_VALUE = "max-age=" + HSTS_MAX_AGE
      VALID_STS_HEADER = /\Amax-age=\d+(; includeSubdomains)?(; preload)?\z/i
      MESSAGE = "The config value supplied for the HSTS header was invalid. Must match #{VALID_STS_HEADER}"
      CONFIG_KEY = :hsts
    end
    include Constants

    def initialize(config = nil)
      @config = config
    end

    def name
      return HSTS_HEADER_NAME
    end

    def value
      if @config.nil?
        DEFAULT_VALUE
      else
        @config
      end
    end

    def self.validate_config!(config)
      return if config.nil?
      raise TypeError.new("Must be a string") unless config.is_a?(String)
      raise STSConfigError.new(MESSAGE) unless config =~ VALID_STS_HEADER
    end
  end
end
