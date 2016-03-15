module SecureHeaders
  class Configuration
    DEFAULT_CONFIG = :default
    NOOP_CONFIGURATION = "secure_headers_noop_config"
    class NotYetConfiguredError < StandardError; end
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
      def override(name, base = DEFAULT_CONFIG)
        unless get(base)
          raise NotYetConfiguredError, "#{base} policy not yet supplied"
        end
        override = @configurations[base].dup
        yield(override)
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

      # Public: perform a basic deep dup. The shallow copy provided by dup/clone
      # can lead to modifying parent objects.
      def deep_copy(config)
        config.each_with_object({}) do |(key, value), hash|
          hash[key] = if value.is_a?(Array)
            value.dup
          else
            value
          end
        end
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
    end

    attr_accessor :hsts, :x_frame_options, :x_content_type_options,
      :x_xss_protection, :csp, :x_download_options, :x_permitted_cross_domain_policies,
      :hpkp, :dynamic_csp, :cached_headers

    def initialize(&block)
      self.hpkp = OPT_OUT
      self.csp = self.class.deep_copy(CSP::DEFAULT_CONFIG)
      instance_eval &block if block_given?
    end

    # Public: copy everything but the cached headers
    #
    # Returns a deep-dup'd copy of this configuration.
    def dup
      copy = self.class.new
      copy.hsts = hsts
      copy.x_frame_options = x_frame_options
      copy.x_content_type_options = x_content_type_options
      copy.x_xss_protection = x_xss_protection
      copy.x_download_options = x_download_options
      copy.x_permitted_cross_domain_policies = x_permitted_cross_domain_policies
      copy.csp = deep_copy_hash(csp)
      copy.dynamic_csp = deep_copy_hash(dynamic_csp)
      copy.hpkp = deep_copy_hash(hpkp)
      copy.cached_headers = deep_copy_hash(cached_headers)
      copy
    end

    # Public: generated cached headers for a specific user agent.
    def rebuild_csp_header_cache!(user_agent)
      self.cached_headers[CSP::CONFIG_KEY] = {}
      unless current_csp == OPT_OUT
        user_agent = UserAgent.parse(user_agent)
        variation = CSP.ua_to_variation(user_agent)
        self.cached_headers[CSP::CONFIG_KEY][variation] = CSP.make_header(current_csp, user_agent)
      end
    end

    # Public: Retrieve a config based on the CONFIG_KEY for a class
    #
    # Returns the value if available, and returns a dup of any hash values.
    def fetch(key)
      config = send(key)
      config = self.class.deep_copy(config) if config.is_a?(Hash)
      config
    end

    def current_csp
      self.dynamic_csp || self.csp
    end

    # Public: validates all configurations values.
    #
    # Raises various configuration errors if any invalid config is detected.
    #
    # Returns nothing
    def validate_config!
      StrictTransportSecurity.validate_config!(hsts)
      ContentSecurityPolicy.validate_config!(csp)
      XFrameOptions.validate_config!(x_frame_options)
      XContentTypeOptions.validate_config!(x_content_type_options)
      XXssProtection.validate_config!(x_xss_protection)
      XDownloadOptions.validate_config!(x_download_options)
      XPermittedCrossDomainPolicies.validate_config!(x_permitted_cross_domain_policies)
      PublicKeyPins.validate_config!(hpkp)
    end

    # Public: Precompute the header names and values for this configuraiton.
    # Ensures that headers generated at configure time, not on demand.
    #
    # Returns the cached headers
    def cache_headers!
      # generate defaults for the "easy" headers
      headers = (ALL_HEADERS_BESIDES_CSP).each_with_object({}) do |klass, hash|
        config = fetch(klass::CONFIG_KEY)
        unless config == OPT_OUT
          hash[klass::CONFIG_KEY] = klass.make_header(config).freeze
        end
      end

      generate_csp_headers(headers)

      headers.freeze
      @cached_headers = headers
    end

    # Private: adds CSP headers for each variation of CSP support.
    #
    # headers - generated headers are added to this hash namespaced by The
    #   different variations
    #
    # Returns nothing
    def generate_csp_headers(headers)
      unless csp == OPT_OUT
        headers[CSP::CONFIG_KEY] = {}
        csp_config = fetch(:current_csp)
        CSP::VARIATIONS.each do |name, _|
          csp = CSP.make_header(csp_config, UserAgent.parse(name))
          headers[CSP::CONFIG_KEY][name] = csp.freeze
        end
      end
    end

    def deep_copy_hash(hash)
      if hash.is_a?(Hash)
        self.class.deep_copy(hash)
      else
        hash
      end
    end
  end
end
