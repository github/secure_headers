# frozen_string_literal: true
require "yaml"

module SecureHeaders
  class Configuration
    DEFAULT_CONFIG = :default
    NOOP_CONFIGURATION = "secure_headers_noop_config"
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
        add_noop_configuration
        add_configuration(DEFAULT_CONFIG, config)
      end
      alias_method :configure, :default

      # Public: create a named configuration that overrides the default config.
      #
      # name - use an idenfier for the override config.
      # base - override another existing config, or override the default config
      # if no value is supplied.
      #
      # Returns: the newly created config
      def override(name, base = DEFAULT_CONFIG, &block)
        unless get(base)
          raise NotYetConfiguredError, "#{base} policy not yet supplied"
        end
        override = @configurations[base].dup
        override.instance_eval(&block) if block_given?
        add_configuration(name, override)
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
        config.send(:cache_headers!)
        config.send(:cache_hpkp_report_host)
        config.freeze
        @configurations[name] = config
      end

      # Private: Automatically add an "opt-out of everything" override.
      #
      # Returns the noop config
      def add_noop_configuration
        noop_config = new do |config|
          ALL_HEADER_CLASSES.each do |klass|
            config.send("#{klass::CONFIG_KEY}=", OPT_OUT)
          end
        end

        add_configuration(NOOP_CONFIGURATION, noop_config)
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

    attr_writer :hsts, :x_frame_options, :x_content_type_options,
      :x_xss_protection, :x_download_options, :x_permitted_cross_domain_policies,
      :referrer_policy, :clear_site_data, :expect_certificate_transparency

    attr_reader :cached_headers, :csp, :cookies, :csp_report_only, :hpkp, :hpkp_report_host

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

    # Public: copy everything but the cached headers
    #
    # Returns a deep-dup'd copy of this configuration.
    def dup
      copy = self.class.new
      copy.cookies = self.class.send(:deep_copy_if_hash, @cookies)
      copy.csp = @csp.dup if @csp
      copy.csp_report_only = @csp_report_only.dup if @csp_report_only
      copy.cached_headers = self.class.send(:deep_copy_if_hash, @cached_headers)
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
      copy.hpkp_report_host = @hpkp_report_host
      copy
    end

    def opt_out(header)
      send("#{header}=", OPT_OUT)
      self.cached_headers.delete(header)
    end

    def update_x_frame_options(value)
      @x_frame_options = value
      self.cached_headers[XFrameOptions::CONFIG_KEY] = XFrameOptions.make_header(value)
    end

    # Public: validates all configurations values.
    #
    # Raises various configuration errors if any invalid config is detected.
    #
    # Returns nothing
    def validate_config!
      StrictTransportSecurity.validate_config!(@hsts)
      ContentSecurityPolicy.validate_config!(@csp)
      ContentSecurityPolicy.validate_config!(@csp_report_only)
      ReferrerPolicy.validate_config!(@referrer_policy)
      XFrameOptions.validate_config!(@x_frame_options)
      XContentTypeOptions.validate_config!(@x_content_type_options)
      XXssProtection.validate_config!(@x_xss_protection)
      XDownloadOptions.validate_config!(@x_download_options)
      XPermittedCrossDomainPolicies.validate_config!(@x_permitted_cross_domain_policies)
      ClearSiteData.validate_config!(@clear_site_data)
      ExpectCertificateTransparency.validate_config!(@expect_certificate_transparency)
      PublicKeyPins.validate_config!(@hpkp)
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

    protected

    def cookies=(cookies)
      @cookies = cookies
    end

    def cached_headers=(headers)
      @cached_headers = headers
    end

    def hpkp=(hpkp)
      @hpkp = self.class.send(:deep_copy_if_hash, hpkp)
    end

    def hpkp_report_host=(hpkp_report_host)
      @hpkp_report_host = hpkp_report_host
    end

    private

    def cache_hpkp_report_host
      has_report_uri = @hpkp && @hpkp != OPT_OUT && @hpkp[:report_uri]
      self.hpkp_report_host = if has_report_uri
        parsed_report_uri = URI.parse(@hpkp[:report_uri])
        parsed_report_uri.host
      end
    end

    # Public: Precompute the header names and values for this configuration.
    # Ensures that headers generated at configure time, not on demand.
    #
    # Returns the cached headers
    def cache_headers!
      # generate defaults for the "easy" headers
      headers = (ALL_HEADERS_BESIDES_CSP).each_with_object({}) do |klass, hash|
        config = instance_variable_get("@#{klass::CONFIG_KEY}")
        unless config == OPT_OUT
          hash[klass::CONFIG_KEY] = klass.make_header(config).freeze
        end
      end

      generate_csp_headers(headers)

      headers.freeze
      self.cached_headers = headers
    end

    # Private: adds CSP headers for each variation of CSP support.
    #
    # headers - generated headers are added to this hash namespaced by The
    #   different variations
    #
    # Returns nothing
    def generate_csp_headers(headers)
      generate_csp_headers_for_config(headers, ContentSecurityPolicyConfig::CONFIG_KEY, self.csp)
      generate_csp_headers_for_config(headers, ContentSecurityPolicyReportOnlyConfig::CONFIG_KEY, self.csp_report_only)
    end

    def generate_csp_headers_for_config(headers, header_key, csp_config)
      unless csp_config.opt_out?
        headers[header_key] = {}
        ContentSecurityPolicy::VARIATIONS.each_key do |name|
          csp = ContentSecurityPolicy.make_header(csp_config, UserAgent.parse(name))
          headers[header_key][name] = csp.freeze
        end
      end
    end
  end
end
