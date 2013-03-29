module SecureHeaders
  class STSBuildError < StandardError; end

  class StrictTransportSecurity
    module Constants
      HSTS_HEADER_NAME = 'Strict-Transport-Security'
      HSTS_MAX_AGE = "631138519"
      DEFAULT_VALUE = "max-age=" + HSTS_MAX_AGE
      VALID_STS_HEADER = /\Amax-age=\d+(; includeSubdomains)?\z/i
      MESSAGE = "The config value supplied for the HSTS header was invalid."
    end
    include Constants

    def initialize(config = nil)
      @config = config
      validate_config unless @config.nil?
    end

    def name
      return HSTS_HEADER_NAME
    end

    def value
      case @config
      when String
        return @config
      when NilClass
        return DEFAULT_VALUE
      end

      max_age = @config.fetch(:max_age, HSTS_MAX_AGE).to_s
      value = "max-age=" + max_age
      value += "; includeSubdomains" if @config[:include_subdomains]

      value
    end

    private

    def validate_config
      if @config.is_a? Hash
        if !@config[:max_age]
          raise STSBuildError.new("No max-age was supplied.")
        elsif @config[:max_age].to_s !~ /\A\d+\z/
          raise STSBuildError.new("max-age must be a number. #{@config[:max_age]} was supplied.")
        end
      else
        @config = @config.to_s
        raise STSBuildError.new(MESSAGE) unless @config =~ VALID_STS_HEADER
      end
    end
  end
end
