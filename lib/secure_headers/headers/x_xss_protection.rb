module SecureHeaders
  class XXssProtectionConfigError < StandardError; end
  class XXssProtection < Header
    module Constants
      X_XSS_PROTECTION_HEADER_NAME = 'X-XSS-Protection'
      DEFAULT_VALUE = "1"
      VALID_X_XSS_HEADER = /\A[01](; mode=block)?(; report=.*)?\z/i
      CONFIG_KEY = :x_xss_protection
    end
    include Constants

    def initialize(config=nil)
      @config = config
      self.class.validate_config!(config) if ENV['RAILS_ENV'] == "development"
    end

    def name
      X_XSS_PROTECTION_HEADER_NAME
    end

    def value
      if @config.nil?
        DEFAULT_VALUE
      else String
        @config
      end
    end

    def self.validate_config!(config)
      return if config.nil? || config == SecureHeaders::OPT_OUT
      raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
      raise XXssProtectionConfigError.new("Invalid format (see VALID_X_XSS_HEADER)") unless config.to_s =~ VALID_X_XSS_HEADER
    end
  end
end
