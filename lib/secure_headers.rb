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
require "secure_headers/railtie"
require "secure_headers/view_helper"

# All headers (except for hpkp) have a default value. Provide SecureHeaders::OPT_OUT
# or ":optout_of_protection" as a config value to disable a given header
module SecureHeaders
  CSP = SecureHeaders::ContentSecurityPolicy

  OPT_OUT = :optout_of_protection
  SCRIPT_HASH_CONFIG_FILE = 'config/script_hashes.yml'
  SECURE_HEADERS_CONFIG = "secure_headers"
  NONCE_KEY = "content_security_policy_nonce"

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
        instance_eval &block
        validate_config!
        @default_headers = SecureHeaders::all_header_hash
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
      ::SecureHeaders::Configuration.send(:hpkp=, OPT_OUT)
      base.module_eval do
        include InstanceMethods
      end
    end

    # Returns all headers for a given config, including headers that
    # may not apply to a given request (e.g. hsts on non-ssl pages)
    def all_header_hash(env = {})
      puts "all headers"
      puts env
      puts request_config
      ALL_HEADER_CLASSES.inject({}) do |memo, klass|
        header_config = env[klass::CONFIG_KEY] ||
          request_config[klass::CONFIG_KEY]

        header = if header_config
          if klass == SecureHeaders::CSP && header_config != SecureHeaders::OPT_OUT
            header_config.merge!(:ua => env["HTTP_USER_AGENT"])
          end
          make_header(klass, header_config)
        else
          SecureHeaders::Configuration::default_headers[klass::CONFIG_KEY] ||
            make_header(klass, SecureHeaders::Configuration.send(klass::CONFIG_KEY))
        end

        memo[header.name] = header.value if header
        memo
      end
    end

    def make_header(klass, header_config)
      unless header_config == OPT_OUT
        klass.new(header_config)
      end
    end

    # Strips out headers not applicable to this request
    def header_hash(env = {})
      puts env
      unless env[:ssl]
        all_header_hash(env).merge(hsts: OPT_OUT, hpkp: OPT_OUT )
      else
        all_header_hash(env)
      end
    end

    def content_security_policy_nonce
      puts "Calling nonce: #{Thread.current[SECURE_HEADERS_CONFIG]}"
      unless request_config[NONCE_KEY]
        request_config[NONCE_KEY] = SecureRandom.base64(32).chomp

        # unsafe-inline is automatically added for backwards compatibility. The spec says to ignore unsafe-inline
        # when a nonce is present
        append_content_security_policy_source(script_src: ["'nonce-#{request_config[NONCE_KEY]}'", CSP::UNSAFE_INLINE])
      end

      request_config[NONCE_KEY]
    end

    def request_config
      Thread.current[SECURE_HEADERS_CONFIG] ||= {}
    end

    def request_config=(config)
      Thread.current[SECURE_HEADERS_CONFIG] = config
    end

    def append_content_security_policy_source(additions)
      config = request_config[SecureHeaders::CSP::CONFIG_KEY] ||
        ::SecureHeaders::Configuration.send(:csp).dup

      config.merge!(additions) do |_, lhs, rhs|
        lhs | rhs
      end
      request_config[SecureHeaders::CSP::CONFIG_KEY] = config
    end

    def override_content_security_policy_directives(additions)
      config = request_config[SecureHeaders::CSP::CONFIG_KEY] ||
        ::SecureHeaders::Configuration.send(:csp).dup
      request_config[SecureHeaders::CSP::CONFIG_KEY] = config.merge(additions)
    end

    private

    def ssl_required?(klass)
      [SecureHeaders::StrictTransportSecurity, SecureHeaders::PublicKeyPins].include?(klass)
    end
  end

  module InstanceMethods
    def request_config
      SecureHeaders::request_config
    end

    def content_security_policy_nonce
      SecureHeaders::content_security_policy_nonce
    end

    # Append value to the source list for the provided directives, override 'none' values
    def append_content_security_policy_source(additions)
      SecureHeaders::append_content_security_policy_source(additions)
    end

    # Overrides the previously set source list for the provided directives, override 'none' values
    def override_content_security_policy_directives(additions)
      SecureHeaders::override_content_security_policy_directive(additions)
    end

    def override_x_frame_options(value)
      raise "override_x_frame_options may only be called once per action." if SecureHeaders::request_config[SecureHeaders::XFrameOptions::CONFIG_KEY]
      SecureHeaders::request_config[SecureHeaders::XFrameOptions::CONFIG_KEY] = value
    end

    def override_hpkp(config)
      raise "override_hpkp may only be called once per action." if SecureHeaders::request_config[SecureHeaders::PublicKeyPins::CONFIG_KEY]
      SecureHeaders::request_config[SecureHeaders::PublicKeyPins::CONFIG_KEY] = config
    end
  end
end
