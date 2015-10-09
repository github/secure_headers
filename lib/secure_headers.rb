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
require "secure_headers/hash_helper"
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
    SecureHeaders::CSP,
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
        :x_xss_protection, :csp, :x_download_options, :script_hashes,
        :x_permitted_cross_domain_policies, :hpkp

      def configure(&block)
        instance_eval &block
        if File.exists?(SCRIPT_HASH_CONFIG_FILE)
          ::SecureHeaders::Configuration.script_hashes = YAML.load(File.open(SCRIPT_HASH_CONFIG_FILE))
        end
      end

      def validate_config!
        StrictTransportSecurity.validate_config!(self.hsts)
        CSP.validate_config!(self.csp)
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

    def header_hash(env)
      RequestLocals.store[SECURE_HEADERS_CONFIG] ||= {}
      ALL_HEADER_CLASSES.inject({}) do |memo, klass|
        header_config = env[klass::Constants::CONFIG_KEY] ||
          RequestLocals.fetch(SECURE_HEADERS_CONFIG) { {} }[klass::Constants::CONFIG_KEY] ||
          SecureHeaders::Configuration.send(klass::Constants::CONFIG_KEY)

        unless header_config == OPT_OUT || (ssl_required?(klass) && env[:ssl] != true)
          header = if klass == SecureHeaders::CSP
            header_config.merge!(:ua => env["HTTP_USER_AGENT"]) if header_config
            CSP.new(header_config)
          else
            klass.new(header_config)
          end

          memo[header.name] = header.value
        end

        memo
      end
    end

    def content_security_policy_nonce
      puts "Calling nonce: #{RequestLocals.fetch(SECURE_HEADERS_CONFIG)}"
      RequestLocals.store[SECURE_HEADERS_CONFIG] ||= {}
      unless RequestLocals.fetch(SECURE_HEADERS_CONFIG)[NONCE_KEY]
        RequestLocals.store[SECURE_HEADERS_CONFIG][NONCE_KEY] = SecureRandom.base64(32).chomp

        # unsafe-inline is automatically added for backwards compatibility. The spec says to ignore unsafe-inline
        # when a nonce is present
        append_content_security_policy_source(script_src: ["'nonce-#{RequestLocals.store[SECURE_HEADERS_CONFIG][NONCE_KEY]}'", CSP::UNSAFE_INLINE])
      end

      RequestLocals.store[SECURE_HEADERS_CONFIG][NONCE_KEY]
    end

    def append_content_security_policy_source(additions)
      RequestLocals.store[SECURE_HEADERS_CONFIG] ||= {}
      config = if RequestLocals.fetch(SECURE_HEADERS_CONFIG)[SecureHeaders::CSP::CONFIG_KEY]
        RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::CSP::CONFIG_KEY]
      else
        ::SecureHeaders::Configuration.send(:csp)
      end

      config.merge!(additions) do |_, lhs, rhs|
        lhs | rhs
      end
      RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::CSP::CONFIG_KEY] = config
    end

    private

    def ssl_required?(klass)
      [SecureHeaders::StrictTransportSecurity, SecureHeaders::PublicKeyPins].include?(klass)
    end
  end

  module InstanceMethods
    def secure_headers_config
      RequestLocals.fetch(SECURE_HEADERS_CONFIG)
    end

    def content_security_policy_nonce
      SecureHeaders::content_security_policy_nonce
    end

    # Append value to the source list for the provided directives, override 'none' values
    def append_content_security_policy_source(additions)
      SecureHeaders::append_content_security_policy_source(additions)
    end

    # Overrides the previously set source list for the provided directives, override 'none' values
    def override_content_security_policy_directive(additions)
      RequestLocals.store[SECURE_HEADERS_CONFIG] ||= {}
      config = if RequestLocals.fetch(SECURE_HEADERS_CONFIG)[SecureHeaders::CSP::CONFIG_KEY]
        RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::CSP::CONFIG_KEY]
      else
        ::SecureHeaders::Configuration.send(:csp)
      end
      RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::CSP::CONFIG_KEY] = config.merge(additions)
    end

    def override_x_frame_options(value)
      raise "override_x_frame_options may only be called once per action." if RequestLocals.fetch(SECURE_HEADERS_CONFIG)[SecureHeaders::XFrameOptions::CONFIG_KEY]
      RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::XFrameOptions::CONFIG_KEY] = value
    end

    def override_hpkp(config)
      raise "override_hpkp may only be called once per action." if RequestLocals.fetch(SECURE_HEADERS_CONFIG)[SecureHeaders::PublicKeyPins::CONFIG_KEY]
      RequestLocals.store[SECURE_HEADERS_CONFIG][SecureHeaders::PublicKeyPins::CONFIG_KEY] = config
    end

    def prep_script_hash
      ActiveSupport::Notifications.subscribe("render_partial.action_view") do |event_name, start_at, end_at, id, payload|
        save_hash_for_later payload
      end

      ActiveSupport::Notifications.subscribe("render_template.action_view") do |event_name, start_at, end_at, id, payload|
        save_hash_for_later payload
      end
    end

    def save_hash_for_later payload
      raise 'not implemented'
    end
  end
end
