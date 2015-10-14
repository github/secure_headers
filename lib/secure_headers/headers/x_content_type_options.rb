module SecureHeaders
  class XContentTypeOptionsConfigError < StandardError; end
  # IE only
  class XContentTypeOptions < Header
    X_CONTENT_TYPE_OPTIONS_HEADER_NAME = "X-Content-Type-Options"
    DEFAULT_VALUE = "nosniff"
    CONFIG_KEY = :x_content_type_options

    class << self
      def make_header(config)
        validate_config!(config) if ENV["RAILS_ENV"] == "development"
        [X_CONTENT_TYPE_OPTIONS_HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        unless config.casecmp(DEFAULT_VALUE) == 0
          raise XContentTypeOptionsConfigError.new("Value can only be nil or 'nosniff'")
        end
      end
    end
  end
end
