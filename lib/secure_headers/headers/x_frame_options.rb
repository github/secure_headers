module SecureHeaders
  class XFOConfigError < StandardError; end
  class XFrameOptions < Header
    XFO_HEADER_NAME = "X-Frame-Options"
    VALID_XFO_HEADER = /\A(SAMEORIGIN\z|DENY\z|ALLOW-FROM[:\s])/i
    CONFIG_KEY = :x_frame_options
    SAMEOROGIN = "SAMEORIGIN"
    DENY = "DENY"
    ALLOW_FROM = "ALLOW-FROM"
    DEFAULT_VALUE = SAMEOROGIN

    class << self
      def make_header(config)
        validate_config!(config) if ENV["RAILS_ENV"] == "development"
        [XFO_HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        unless config =~ VALID_XFO_HEADER
          raise XFOConfigError.new("Value must be SAMEORIGIN|DENY|ALLOW-FROM:")
        end
      end
    end
  end
end
