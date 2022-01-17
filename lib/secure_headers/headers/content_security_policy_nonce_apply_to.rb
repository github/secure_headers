# frozen_string_literal: true
module SecureHeaders
  class CSPNonceApplyToConfigError < StandardError; end

  class ContentSecurityPolicyNonceApplyTo
    ACCEPTABLE_VALUES = [:enforced, :report_only, :both]

    class << self
      def validate_config!(config)
        return if config.nil?
        raise TypeError.new("Must be one of :enforced, :report_only or both. Found #{config.class}: #{config} #{config.class}") unless ACCEPTABLE_VALUES.include?(config)
      end
    end
  end
end
