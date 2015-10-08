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
    end

    def name
      X_XSS_PROTECTION_HEADER_NAME
    end

    def value
      case @config
      when NilClass
        DEFAULT_VALUE
      when String
        @config
      else
        value = @config[:value].to_s
        value += "; mode=#{@config[:mode]}" if @config[:mode]
        value += "; report=#{@config[:report_uri]}" if @config[:report_uri]
        value
      end
    end

    def self.validate_config(config)
      if config.is_a? Hash
        if !config[:value]
          raise XXssProtectionConfigError.new(":value key is missing")
        elsif config[:value]
          unless [0,1].include?(config[:value].to_i)
            raise XXssProtectionConfigError.new(":value must be 1 or 0")
          end

          if config[:mode] && config[:mode].casecmp('block') != 0
            raise XXssProtectionConfigError.new(":mode must nil or 'block'")
          end
        end
      elsif config.is_a? String
        raise XXssProtectionConfigError.new("Invalid format (see VALID_X_XSS_HEADER)") unless config =~ VALID_X_XSS_HEADER
      end
    end
  end
end
