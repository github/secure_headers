# frozen_string_literal: true
require "yaml"

module SecureHeaders
  class Configuration
    DEFAULT_CONFIG = :default
    NOOP_OVERRIDE = "secure_headers_noop_override"
    class NotYetConfiguredError < StandardError; end
    class IllegalPolicyModificationError < StandardError; end
    class << self
      # Public: Set the global default configuration.
      #
      # Optionally supply a block to override the defaults set by this library.
      #
      # Returns the newly created config.
      def default(&block)
        config = new(&block)
        add_configuration(DEFAULT_CONFIG, config)
        override(NOOP_OVERRIDE) do |config|
          CONFIG_ATTRIBUTES.each do |attr|
            config.instance_variable_set("@#{attr}", OPT_OUT)
          end
        end
        config
      end
      alias_method :configure, :default

      # Public: create a named configuration that overrides the default config.
      #
      # name - use an idenfier for the override config.
      # base - override another existing config, or override the default config
      # if no value is supplied.
      #
      # Returns: the newly created config
      def override(name, &block)
        @overrides ||= {}
        @overrides[name] = block
      end

      def overrides(name)
        @overrides ||= {}
        @overrides[name]
      end

      # Public: retrieve a global configuration object
      #
      # Returns the configuration with a given name or raises a
      # NotYetConfiguredError if `default` has not been called.
      def get(name = DEFAULT_CONFIG)
        if @configurations.nil?
          raise NotYetConfiguredError, "Default policy not yet supplied"
        end
        @configurations[name]
      end

      def named_appends(name)
        @appends ||= {}
        @appends[name]
      end

      def named_append(name, target = nil, &block)
        @appends ||= {}
        raise "Provide a configuration block" unless block_given?
        @appends[name] = block
      end

      private

      # Private: add a valid configuration to the global set of named configs.
      #
      # config - the config to store
      # name - the lookup value for this config
      #
      # Raises errors if the config is invalid or if a config named `name`
      # already exists.
      #
      # Returns the config, if valid
      def add_configuration(name, config)
        config.validate_config!
        @configurations ||= {}
        config.freeze
        @configurations[name] = config
      end

      # Public: perform a basic deep dup. The shallow copy provided by dup/clone
      # can lead to modifying parent objects.
      def deep_copy(config)
        return unless config
        config.each_with_object({}) do |(key, value), hash|
          hash[key] = if value.is_a?(Array)
            value.dup
          else
            value
          end
        end
      end

      # Private: convenience method purely DRY things up. The value may not be a
      # hash (e.g. OPT_OUT, nil)
      def deep_copy_if_hash(value)
        if value.is_a?(Hash)
          deep_copy(value)
        else
          value
        end
      end
    end

    NON_HEADER_ATTRIBUTES = [
      :cookies, :hpkp_report_host
    ].freeze

    HEADER_ATTRIBUTES_TO_HEADER_CLASSES = {
      hsts: StrictTransportSecurity,
      x_frame_options: XFrameOptions,
      x_content_type_options: XContentTypeOptions,
      x_xss_protection: XXssProtection,
      x_download_options: XDownloadOptions,
      x_permitted_cross_domain_policies: XPermittedCrossDomainPolicies,
      referrer_policy: ReferrerPolicy,
      clear_site_data: ClearSiteData,
      expect_certificate_transparency: ExpectCertificateTransparency,
      csp: ContentSecurityPolicy,
      csp_report_only: ContentSecurityPolicy,
      hpkp: PublicKeyPins,
    }.freeze

    CONFIG_ATTRIBUTES = (HEADER_ATTRIBUTES_TO_HEADER_CLASSES.keys + NON_HEADER_ATTRIBUTES).freeze

    attr_accessor(*CONFIG_ATTRIBUTES)

    @script_hashes = nil
    @style_hashes = nil

    HASH_CONFIG_FILE = ENV["secure_headers_generated_hashes_file"] || "config/secure_headers_generated_hashes.yml"
    if File.exist?(HASH_CONFIG_FILE)
      config = YAML.safe_load(File.open(HASH_CONFIG_FILE))
      @script_hashes = config["scripts"]
      @style_hashes = config["styles"]
    end

    def initialize(&block)
      @cookies = self.class.send(:deep_copy_if_hash, Cookie::COOKIE_DEFAULTS)
      @clear_site_data = nil
      @csp = nil
      @csp_report_only = nil
      @hpkp_report_host = nil
      @hpkp = nil
      @hsts = nil
      @x_content_type_options = nil
      @x_download_options = nil
      @x_frame_options = nil
      @x_permitted_cross_domain_policies = nil
      @x_xss_protection = nil
      @expect_certificate_transparency = nil

      self.hpkp = OPT_OUT
      self.referrer_policy = OPT_OUT
      self.csp = ContentSecurityPolicyConfig.new(ContentSecurityPolicyConfig::DEFAULT)
      self.csp_report_only = OPT_OUT

      instance_eval(&block) if block_given?
    end

    # Public: copy everything
    #
    # Returns a deep-dup'd copy of this configuration.
    def dup
      copy = self.class.new
      copy.cookies = self.class.send(:deep_copy_if_hash, @cookies)
      copy.csp = @csp.dup if @csp
      copy.csp_report_only = @csp_report_only.dup if @csp_report_only
      copy.x_content_type_options = @x_content_type_options
      copy.hsts = @hsts
      copy.x_frame_options = @x_frame_options
      copy.x_xss_protection = @x_xss_protection
      copy.x_download_options = @x_download_options
      copy.x_permitted_cross_domain_policies = @x_permitted_cross_domain_policies
      copy.clear_site_data = @clear_site_data
      copy.expect_certificate_transparency = @expect_certificate_transparency
      copy.referrer_policy = @referrer_policy
      copy.hpkp = @hpkp
      copy
    end

    def generate_headers(user_agent)
      headers = {}
      HEADER_ATTRIBUTES_TO_HEADER_CLASSES.each do |attr, klass|
        header_name, value = klass.make_header(instance_variable_get("@#{attr}"), user_agent)
        if header_name && value
          headers[header_name] = value
        end
      end
      headers
    end

    def opt_out(header)
      send("#{header}=", OPT_OUT)
    end

    def update_x_frame_options(value)
      @x_frame_options = value
    end

    # Public: validates all configurations values.
    #
    # Raises various configuration errors if any invalid config is detected.
    #
    # Returns nothing
    def validate_config!
      HEADER_ATTRIBUTES_TO_HEADER_CLASSES.each do |attr, klass|
        klass.validate_config!(instance_variable_get("@#{attr}"))
      end
      Cookie.validate_config!(@cookies)
    end

    def secure_cookies=(secure_cookies)
      raise ArgumentError, "#{Kernel.caller.first}: `#secure_cookies=` is no longer supported. Please use `#cookies=` to configure secure cookies instead."
    end

    def csp=(new_csp)
      if new_csp.respond_to?(:opt_out?)
        @csp = new_csp.dup
      else
        if new_csp[:report_only]
          # invalid configuration implies that CSPRO should be set, CSP should not - so opt out
          raise ArgumentError, "#{Kernel.caller.first}: `#csp=` was supplied a config with report_only: true. Use #csp_report_only="
        else
          @csp = ContentSecurityPolicyConfig.new(new_csp)
        end
      end
    end

    # Configures the Content-Security-Policy-Report-Only header. `new_csp` cannot
    # contain `report_only: false` or an error will be raised.
    #
    # NOTE: if csp has not been configured/has the default value when
    # configuring csp_report_only, the code will assume you mean to only use
    # report-only mode and you will be opted-out of enforce mode.
    def csp_report_only=(new_csp)
      @csp_report_only = begin
        if new_csp.is_a?(ContentSecurityPolicyConfig)
          new_csp.make_report_only
        elsif new_csp.respond_to?(:opt_out?)
          new_csp.dup
        else
          if new_csp[:report_only] == false # nil is a valid value on which we do not want to raise
            raise ContentSecurityPolicyConfigError, "`#csp_report_only=` was supplied a config with report_only: false. Use #csp="
          else
            ContentSecurityPolicyReportOnlyConfig.new(new_csp)
          end
        end
      end
    end

    def hpkp_report_host
      return nil unless @hpkp && hpkp != OPT_OUT && @hpkp[:report_uri]
      URI.parse(@hpkp[:report_uri]).host
    end

    protected

    def cookies=(cookies)
      @cookies = cookies
    end

    def hpkp=(hpkp)
      @hpkp = self.class.send(:deep_copy_if_hash, hpkp)
    end
  end
end
