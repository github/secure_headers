module SecureHeaders
  class XContentTypeOptionsConfigError < StandardError; end
  # IE only
  class XContentTypeOptions < Header
    module Constants
      X_CONTENT_TYPE_OPTIONS_HEADER_NAME = "X-Content-Type-Options"
      DEFAULT_VALUE = "nosniff"
      CONFIG_KEY = :x_content_type_options
    end
    include Constants

    def initialize(config=nil)
      @config = config
    end

    def name
      X_CONTENT_TYPE_OPTIONS_HEADER_NAME
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
      unless config.casecmp(DEFAULT_VALUE) == 0
        raise XContentTypeOptionsConfigError.new("Value can only be nil or 'nosniff'")
      end
    end
  end
end
