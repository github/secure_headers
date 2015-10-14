module SecureHeaders
  class XDOConfigError < StandardError; end
  class XDownloadOptions < Header
    XDO_HEADER_NAME = "X-Download-Options"
    DEFAULT_VALUE = 'noopen'
    CONFIG_KEY = :x_download_options

    class << self
      def make_header(config)
        validate_config!(config) if ENV["RAILS_ENV"] == "development"
        [XDO_HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        unless config.casecmp(DEFAULT_VALUE) == 0
          raise XDOConfigError.new("Value can only be nil or 'noopen'")
        end
      end
    end
  end
end
