require "secure_headers/version"
require "secure_headers/header"
require "secure_headers/headers/public_key_pins"
require "secure_headers/headers/content_security_policy"
require "secure_headers/headers/x_frame_options"
require "secure_headers/headers/strict_transport_security"
require "secure_headers/headers/x_xss_protection"
require "secure_headers/headers/x_content_type_options"
require "secure_headers/headers/x_download_options"
require "secure_headers/headers/x_permitted_cross_domain_policies"
require "secure_headers/controller_extension"
require "secure_headers/railtie"
require "secure_headers/hash_helper"
require "secure_headers/view_helper"

module SecureHeaders
  SCRIPT_HASH_CONFIG_FILE = 'config/script_hashes.yml'
  HASHES_ENV_KEY = 'secure_headers.script_hashes'

  ALL_HEADER_CLASSES = [
    SecureHeaders::ContentSecurityPolicy,
    SecureHeaders::StrictTransportSecurity,
    SecureHeaders::PublicKeyPins,
    SecureHeaders::XContentTypeOptions,
    SecureHeaders::XDownloadOptions,
    SecureHeaders::XFrameOptions,
    SecureHeaders::XPermittedCrossDomainPolicies,
    SecureHeaders::XXssProtection
  ]

  ALL_FILTER_METHODS = [
    :prep_script_hash,
    :set_hsts_header,
    :set_hpkp_header,
    :set_x_frame_options_header,
    :set_csp_header,
    :set_x_xss_protection_header,
    :set_x_content_type_options_header,
    :set_x_download_options_header,
    :set_x_permitted_cross_domain_policies_header
  ]

  module Configuration
    class << self
      attr_accessor :hsts, :x_frame_options, :x_content_type_options,
        :x_xss_protection, :csp, :x_download_options, :script_hashes,
        :x_permitted_cross_domain_policies, :hpkp

      # For preparation for the secure_headers 3.x change.
      def default &block
        instance_eval &block
        if File.exists?(SCRIPT_HASH_CONFIG_FILE)
          ::SecureHeaders::Configuration.script_hashes = YAML.load(File.open(SCRIPT_HASH_CONFIG_FILE))
        end
      end

      def configure &block
        warn "[DEPRECATION] `configure` is removed in secure_headers 3.x. Instead use `default`."
        default &block
      end
    end
  end

  class << self
    def append_features(base)
      base.send(:include, ControllerExtension)
    end

    def header_hash(options = nil)
      ALL_HEADER_CLASSES.inject({}) do |memo, klass|
        # must use !options[key].nil? because 'false' represents opting out, nil
        # represents use global default.
        config = if options.is_a?(Hash) && !options[klass::Constants::CONFIG_KEY].nil?
          options[klass::Constants::CONFIG_KEY]
        else
          ::SecureHeaders::Configuration.send(klass::Constants::CONFIG_KEY)
        end

        unless klass == SecureHeaders::PublicKeyPins && !config.is_a?(Hash)
          header = get_a_header(klass, config)
          memo[header.name] = header.value if header
        end
        memo
      end
    end

    def get_a_header(klass, options)
      return if options == false
      klass.new(options)
    end
  end

end
