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
  @secure_headers_mutex = Mutex.new

  OPT_OUT = :optout_of_protection
  SCRIPT_HASH_CONFIG_FILE = 'config/script_hashes.yml'
  HASHES_ENV_KEY = 'secure_headers.script_hashes'
  CSP_ENV_KEY = "secure_headers.#{ContentSecurityPolicy::CONFIG_KEY}"
  XFO_ENV_KEY = "secure_headers.#{XFrameOptions::CONFIG_KEY}"
  HPKP_ENV_KEY = "secure_headers.#{PublicKeyPins::CONFIG_KEY}"
  SECURE_HEADERS_CONFIG = "secure_headers"
  NONCE_KEY = "secure_headers.content_security_policy_nonce"

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

    def header_hash(env = {})
      ALL_HEADER_CLASSES.inject({}) do |memo, klass|
        config = env["secure_headers.#{klass::Constants::CONFIG_KEY}"] ||
          env[klass::Constants::CONFIG_KEY]                            ||
          ::SecureHeaders::Configuration.send(klass::Constants::CONFIG_KEY)

        unless config == OPT_OUT || (ssl_required?(klass) && env[:ssl] != true)
          header = if klass == SecureHeaders::ContentSecurityPolicy
            config.merge!(:ua => env["HTTP_USER_AGENT"]) if config
            ContentSecurityPolicy.new(config)
          else
            klass.new(config)
          end

          memo[header.name] = header.value
        end

        memo
      end
    end

    def append_content_security_policy_source(env, additions)
      @secure_headers_mutex.synchronize do
        config = if env[CSP_ENV_KEY]
          env[CSP_ENV_KEY]
        else
          ::SecureHeaders::Configuration.send(:csp)
        end

        config.merge!(additions) do |_, lhs, rhs|
          lhs | rhs
        end
        env[CSP_ENV_KEY] = config
      end
    end

   # Overrides the previously set source list for the provided directives, override 'none' values
    def override_content_security_policy_directive(env, additions)
      @secure_headers_mutex.synchronize do
        config = if env[CSP_ENV_KEY]
          env[CSP_ENV_KEY]
        else
          ::SecureHeaders::Configuration.send(:csp)
        end
        env[CSP_ENV_KEY] = config.merge(additions)
      end
    end

    def content_security_policy_nonce(env)
      unless env[NONCE_KEY]
        @secure_headers_mutex.synchronize do
          env[NONCE_KEY] = SecureRandom.base64(32).chomp
        end

        # unsafe-inline is automatically added for backwards compatibility. The spec says to ignore unsafe-inline
        # when a nonce is present
        append_content_security_policy_source(env, script_src: ["'nonce-#{env[NONCE_KEY]}'", ContentSecurityPolicy::UNSAFE_INLINE])
      end

      env[NONCE_KEY]
    end

    private

    def ssl_required?(klass)
      [SecureHeaders::StrictTransportSecurity, SecureHeaders::PublicKeyPins].include?(klass)
    end
  end

  module InstanceMethods
    def secure_headers_config
      request.env[SECURE_HEADERS_CONFIG]
    end

    def content_security_policy_nonce
      SecureHeaders.content_security_policy_nonce(request.env)
    end

    # Append value to the source list for the provided directives, override 'none' values
    def append_content_security_policy_source(additions)
      SecureHeaders.append_content_security_policy_source(request.env, additions)
    end

    # Overrides the previously set source list for the provided directives, override 'none' values
    def override_content_security_policy_directive(additions)
      SecureHeaders.override_content_security_policy_directive(request.env, additions)
    end

    def override_x_frame_options(value)
      raise "override_x_frame_options may only be called once per action." if request.env[XFO_ENV_KEY]
      request.env[XFO_ENV_KEY] = value
    end

    def override_hpkp(config)
      raise "override_hpkp may only be called once per action." if request.env[HPKP_ENV_KEY]
      request.env[HPKP_ENV_KEY] = config
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
