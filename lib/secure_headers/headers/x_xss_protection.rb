module SecureHeaders
  class XXssProtectionBuildError < StandardError; end
  # IE only
  class XXssProtection
    module Constants
      X_XSS_PROTECTION_HEADER_NAME = 'X-XSS-Protection'
      DEFAULT_VALUE = "1"
      VALID_X_XSS_HEADER = /\A[01](; mode=block)?\z/i
    end
    include Constants

    def initialize(config=nil)
      @config = config
      validate_config unless @config.nil?
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
        value
      end
    end

    private

    def validate_config
      if @config.is_a? Hash
        if !@config[:value]
          raise XXssProtectionBuildError.new(":value key is missing")
        elsif @config[:value]
          unless [0,1].include?(@config[:value].to_i)
            raise XXssProtectionBuildError.new(":value must be 1 or 0")
          end

          if @config[:mode] && @config[:mode].casecmp('block') != 0
            raise XXssProtectionBuildError.new(":mode must nil or 'block'")
          end
        end
      elsif @config.is_a? String
        raise XXssProtectionBuildError.new("Invalid format (see VALID_X_XSS_HEADER)") unless @config =~ VALID_X_XSS_HEADER
      end
    end
  end
end