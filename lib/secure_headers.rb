require 'request_store_rails'
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
require "secure_headers/middleware"
require "secure_headers/railtie"
require "secure_headers/view_helper"

# All headers (except for hpkp) have a default value. Provide SecureHeaders::OPT_OUT
# or ":optout_of_protection" as a config value to disable a given header
module SecureHeaders
  CSP = SecureHeaders::ContentSecurityPolicy

  OPT_OUT = :optout_of_protection
  SCRIPT_HASH_CONFIG_FILE = "config/script_hashes.yml".freeze
  SECURE_HEADERS_CONFIG = "secure_headers".freeze
  NONCE_KEY = "content_security_policy_nonce".freeze
  HTTPS = "https".freeze

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

  module Configuration
    class << self
      attr_accessor :hsts, :x_frame_options, :x_content_type_options,
        :x_xss_protection, :csp, :x_download_options, :x_permitted_cross_domain_policies,
        :hpkp

      def default_headers
        @default_headers ||= {}
      end

      def configure(&block)
        self.hpkp = OPT_OUT
        instance_eval &block
        validate_config!
        # TODO pre-generate all header values, including matrix support for CSP
        # @default_headers = SecureHeaders::generate_default_headers
      end

      def fetch(key)
        config = self.send(key)
        config = config.dup if config.is_a?(Hash)
        config
      end

      def validate_config!
        StrictTransportSecurity.validate_config!(self.hsts)
        ContentSecurityPolicy.validate_config!(self.csp)
        XFrameOptions.validate_config!(self.x_frame_options)
        XContentTypeOptions.validate_config!(self.x_content_type_options)
        XXssProtection.validate_config!(self.x_xss_protection)
        XDownloadOptions.validate_config!(self.x_download_options)
        XPermittedCrossDomainPolicies.validate_config!(self.x_permitted_cross_domain_policies)
        PublicKeyPins.validate_config!(self.hpkp)
      end
    end
  end

  class << self
    def append_features(base)
      # HPKP is the only header not set by default, so opt it out here
      base.module_eval do
        include InstanceMethods
      end
    end

    # Strips out headers not applicable to this request
    def header_hash_for(request)
      unless request.scheme == HTTPS
        secure_headers_request_config(request)[SecureHeaders::StrictTransportSecurity::CONFIG_KEY] = SecureHeaders::OPT_OUT
        secure_headers_request_config(request)[SecureHeaders::PublicKeyPins::CONFIG_KEY] = SecureHeaders::OPT_OUT
      end

      ALL_HEADER_CLASSES.inject({}) do |memo, klass|
        header_config = request.env[klass::CONFIG_KEY] ||
          secure_headers_request_config(request)[klass::CONFIG_KEY]

        header_name, header = if header_config
          # TODO generate policies bucketed by browser capabilities
          if klass == SecureHeaders::CSP && header_config != SecureHeaders::OPT_OUT
            header_config.merge!(:ua => request.user_agent)
          end
          make_header(klass, header_config)
        else
          # use the cached default, if available
          if default_header = SecureHeaders::Configuration::default_headers[klass::CONFIG_KEY]
            default_header
          else
            if default_config = SecureHeaders::Configuration.fetch(klass::CONFIG_KEY)
              # use the default configuration value
              make_header(klass, default_config)
            else
              # use the default value for the class
              make_header(klass, nil)
            end
          end
        end

        memo[header_name] = header if header
        memo
      end
    end

    def make_header(klass, header_config)
      unless header_config == OPT_OUT
        klass.make_header(header_config)
      end
    end

    def opt_out_of(request, header_key)
      SecureHeaders::secure_headers_request_config(request)[header_key] = SecureHeaders::OPT_OUT
    end

    def content_security_policy_nonce(request)
      unless secure_headers_request_config(request)[NONCE_KEY]
        secure_headers_request_config(request)[NONCE_KEY] = SecureRandom.base64(32).chomp

        # unsafe-inline is automatically added for backwards compatibility. The spec says to ignore unsafe-inline
        # when a nonce is present
        append_content_security_policy_source(request, script_src: ["'nonce-#{secure_headers_request_config(request)[NONCE_KEY]}'", CSP::UNSAFE_INLINE])
      end

      secure_headers_request_config(request)[NONCE_KEY]
    end

    def secure_headers_request_config(request)
      request.env[SECURE_HEADERS_CONFIG] ||= {}
    end

    def append_content_security_policy_source(request, additions)
      config = secure_headers_request_config(request)[SecureHeaders::CSP::CONFIG_KEY] ||
        SecureHeaders::Configuration.fetch(:csp)

      config.merge!(additions) do |_, lhs, rhs|
        lhs | rhs
      end
      secure_headers_request_config(request)[SecureHeaders::CSP::CONFIG_KEY] = config
    end

    def override_content_security_policy_directives(request, additions)
      config = secure_headers_request_config(request)[SecureHeaders::CSP::CONFIG_KEY] ||
        SecureHeaders::Configuration.fetch(:csp) || {}
      secure_headers_request_config(request)[SecureHeaders::CSP::CONFIG_KEY] = config.merge(additions)
    end
  end

  module InstanceMethods
    def secure_headers_request_config
      SecureHeaders::secure_headers_request_config(request)
    end

    def content_security_policy_nonce
      SecureHeaders::content_security_policy_nonce(request)
    end

    def opt_out_of(header_key)
      SecureHeaders::opt_out_of(request, header_key)
    end

    # Append value to the source list for the provided directives, override 'none' values
    def append_content_security_policy_source(additions)
      SecureHeaders::append_content_security_policy_source(request, additions)
    end

    # Overrides the previously set source list for the provided directives, override 'none' values
    def override_content_security_policy_directives(additions)
      SecureHeaders::override_content_security_policy_directive(additions)
    end

    def override_x_frame_options(value)
      raise "override_x_frame_options may only be called once per action." if SecureHeaders::secure_headers_request_config(request)[SecureHeaders::XFrameOptions::CONFIG_KEY]
      SecureHeaders::secure_headers_request_config(request)[SecureHeaders::XFrameOptions::CONFIG_KEY] = value
    end

    def override_hpkp(config)
      raise "override_hpkp may only be called once per action." if SecureHeaders::secure_headers_request_config(request)[SecureHeaders::PublicKeyPins::CONFIG_KEY]
      SecureHeaders::secure_headers_request_config(request)[SecureHeaders::PublicKeyPins::CONFIG_KEY] = config
    end
  end
end
