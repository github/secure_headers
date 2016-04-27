module SecureHeaders
  class ReferrerPolicyConfigError < StandardError; end
  class ReferrerPolicy
    HEADER_NAME = "Referrer-Policy"
    DEFAULT_VALUE = "origin-when-cross-origin"
    VALID_POLICIES = %w(
      no-referrer
      no-referrer-when-downgrade
      origin
      origin-when-cross-origin
      unsafe-url
    )
    CONFIG_KEY = :referrer_policy

    class << self
      # Public: generate an Referrer Policy header.
      #
      # Returns a default header if no configuration is provided, or a
      # header name and value based on the config.
      def make_header(config = nil)
        [HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        unless VALID_POLICIES.include?(config.downcase)
          raise ReferrerPolicyConfigError.new("Value can only be one of #{VALID_POLICIES.join(', ')}")
        end
      end
    end
  end
end
