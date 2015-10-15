module SecureHeaders
  class XFOConfigError < StandardError; end
  class XFrameOptions < Header
    HEADER_NAME = "X-Frame-Options"
    VALID_XFO_HEADER = /\A(SAMEORIGIN\z|DENY\z|ALLOW-FROM[:\s])/i
    CONFIG_KEY = :x_frame_options
    SAMEOROGIN = "SAMEORIGIN"
    DENY = "DENY"
    ALLOW_FROM = "ALLOW-FROM"
    DEFAULT_VALUE = SAMEOROGIN

    class << self
      def make_header(config = nil)
        return if config == SecureHeaders::OPT_OUT
        validate_config!(config) if validate_config?
        [HEADER_NAME, config || DEFAULT_VALUE]
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
