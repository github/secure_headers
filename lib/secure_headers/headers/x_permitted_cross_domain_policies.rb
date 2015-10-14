module SecureHeaders
  class XPCDPConfigError < StandardError; end
  class XPermittedCrossDomainPolicies < Header
    HEADER_NAME = "X-Permitted-Cross-Domain-Policies"
    DEFAULT_VALUE = 'none'
    VALID_POLICIES = %w(all none master-only by-content-type by-ftp-filename)
    CONFIG_KEY = :x_permitted_cross_domain_policies

    class << self
      def make_header(config = nil)
        validate_config!(config) if validate_config?
        [HEADER_NAME, config || DEFAULT_VALUE]
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise TypeError.new("Must be a string. Found #{config.class}: #{config}") unless config.is_a?(String)
        unless VALID_POLICIES.include?(config.downcase)
          raise XPCDPConfigError.new("Value can only be one of #{VALID_POLICIES.join(', ')}")
        end
      end
    end
  end
end
