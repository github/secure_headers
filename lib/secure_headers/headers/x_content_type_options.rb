module SecureHeaders
  class XContentTypeOptionsBuildError < StandardError; end
  # IE only
  class XContentTypeOptions < Header
    module Constants
      X_CONTENT_TYPE_OPTIONS_HEADER_NAME = "X-Content-Type-Options"
      DEFAULT_VALUE = "nosniff"
    end
    include Constants

    def initialize(config=nil)
      @config = config
      validate_config unless @config.nil?
    end

    def name
      X_CONTENT_TYPE_OPTIONS_HEADER_NAME
    end

    def value
      case @config
      when NilClass
        DEFAULT_VALUE
      when String
        @config
      else
        @config[:value]
      end
    end

    private

    def validate_config
      value = @config.is_a?(Hash) ? @config[:value] : @config
      unless value.casecmp(DEFAULT_VALUE) == 0
        raise XContentTypeOptionsBuildError.new("Value can only be nil or 'nosniff'")
      end
    end
  end
end