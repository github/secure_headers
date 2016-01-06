module SecureHeaders
  class XPCDPBuildError < StandardError; end
  class XPermittedCrossDomainPolicies < Header
    module Constants
      XPCDP_HEADER_NAME = "X-Permitted-Cross-Domain-Policies"
      DEFAULT_VALUE = 'none'
      VALID_POLICIES = %w(all none master-only by-content-type by-ftp-filename)
      CONFIG_KEY = :x_permitted_cross_domain_policies
    end
    include Constants

    def initialize(config = nil)
      @config = config
      validate_config unless @config.nil?
    end

    def name
      XPCDP_HEADER_NAME
    end

    def value
      case @config
      when NilClass
        DEFAULT_VALUE
      when String
        @config
      else
        warn "[DEPRECATION] secure_headers 3.0 will only accept string values for XPermittedCrossDomainPolicies config"
        @config[:value]
      end
    end

    private

    def validate_config
      value = @config.is_a?(Hash) ? @config[:value] : @config
      unless VALID_POLICIES.include?(value.downcase)
        raise XPCDPBuildError.new("Value can only be one of #{VALID_POLICIES.join(', ')}")
      end
    end
  end
end
