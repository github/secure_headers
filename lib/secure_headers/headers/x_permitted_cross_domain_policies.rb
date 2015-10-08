module SecureHeaders
  class XPCDPConfigError < StandardError; end
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
        @config[:value]
      end
    end

    def self.validate_config(config)
      return if config.nil?
      value = config.is_a?(Hash) ? config[:value] : config
      unless VALID_POLICIES.include?(value.downcase)
        raise XPCDPConfigError.new("Value can only be one of #{VALID_POLICIES.join(', ')}")
      end
    end
  end
end
