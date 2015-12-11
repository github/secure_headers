require "secure_headers/configuration"
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
require "useragent"

# All headers (except for hpkp) have a default value. Provide SecureHeaders::OPT_OUT
# or ":optout_of_protection" as a config value to disable a given header
module SecureHeaders
  OPT_OUT = :opt_out_of_protection
  SECURE_HEADERS_CONFIG = "secure_headers_request_config".freeze
  NONCE_KEY = "secure_headers_content_security_policy_nonce".freeze
  HTTPS = "https".freeze
  CSP = ContentSecurityPolicy

  ALL_HEADER_CLASSES = [
    ContentSecurityPolicy,
    StrictTransportSecurity,
    PublicKeyPins,
    XContentTypeOptions,
    XDownloadOptions,
    XFrameOptions,
    XPermittedCrossDomainPolicies,
    XXssProtection
  ].freeze

  ALL_HEADERS_BESIDES_CSP = (ALL_HEADER_CLASSES - [CSP]).freeze

  # Headers set on http requests (excludes STS and HPKP)
  HTTP_HEADER_CLASSES =
    (ALL_HEADER_CLASSES - [StrictTransportSecurity, PublicKeyPins]).freeze

  class << self
    # Public: override a given set of directives for the current request. If a
    # value already exists for a given directive, it will be overridden.
    #
    # If CSP was previously OPT_OUT, a new blank policy is used.
    #
    # additions - a hash containing directives. e.g.
    #    script_src: %w(another-host.com)
    def override_content_security_policy_directives(request, additions)
      config = config_for(request).dup
      if config.csp == OPT_OUT
        config.csp = {}
      end
      config.csp.merge!(additions)
      override_secure_headers_request_config(request, config)
    end

    # Public: appends source values to the current configuration. If no value
    # is set for a given directive, the value will be merged with the default-src
    # value. If a value exists for the given directive, the values will be combined.
    #
    # additions - a hash containing directives. e.g.
    #    script_src: %w(another-host.com)
    def append_content_security_policy_directives(request, additions)
      config = config_for(request).dup
      config.csp = CSP.combine_policies(config.csp, additions)
      override_secure_headers_request_config(request, config)
    end

    # Public: override X-Frame-Options settings for this request.
    #
    # value - deny, sameorigin, or allowall
    #
    # Returns the current config
    def override_x_frame_options(request, value)
      default_config = config_for(request).dup
      default_config.x_frame_options = value
      override_secure_headers_request_config(request, default_config)
    end

    # Public: opts out of setting a given header by creating a temporary config
    # and setting the given headers config to OPT_OUT.
    def opt_out_of_header(request, header_key)
      config = config_for(request).dup
      config.send("#{header_key}=", OPT_OUT)
      override_secure_headers_request_config(request, config)
    end

    # Public: opts out of setting all headers by telling secure_headers to use
    # the NOOP configuration.
    def opt_out_of_all_protection(request)
      use_secure_headers_override(request, Configuration::NOOP_CONFIGURATION)
    end

    # Public: Builds the hash of headers that should be applied base on the
    # request.
    #
    # StrictTransportSecurity and PublicKeyPins are not applied to http requests.
    # See #config_for to determine which config is used for a given request.
    #
    # Returns a hash of header names => header values. The value
    # returned is meant to be merged into the header value from `@app.call(env)`
    # in Rack middleware.
    def header_hash_for(request)
      config = config_for(request)

      headers = if cached_headers = config.cached_headers
        use_cached_headers(cached_headers, request)
      else
        build_headers(config, request)
      end

      headers
    end

    # Public: specify which named override will be used for this request.
    # Raises an argument error if no named override exists.
    #
    # name - the name of the previously configured override.
    def use_secure_headers_override(request, name)
      if config = Configuration.get(name)
        override_secure_headers_request_config(request, config)
      else
        raise ArgumentError.new("no override by the name of #{name} has been configured")
      end
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to script_src
    #
    # Returns the nonce
    def content_security_policy_script_nonce(request)
      content_security_policy_nonce(request, CSP::SCRIPT_SRC)
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to style_src
    #
    # Returns the nonce
    def content_security_policy_style_nonce(request)
      content_security_policy_nonce(request, CSP::STYLE_SRC)
    end

    private

    # Private: gets or creates a nonce for CSP.
    #
    # Returns the nonce
    def content_security_policy_nonce(request, script_or_style)
      request.env[NONCE_KEY] ||= SecureRandom.base64(32).chomp
      nonce_key = script_or_style == CSP::SCRIPT_SRC ? :script_nonce : :style_nonce
      append_content_security_policy_directives(request, nonce_key => request.env[NONCE_KEY])
      request.env[NONCE_KEY]
    end

    # Private: convenience method for specifying which configuration object should
    # be used for this request.
    #
    # Returns the config.
    def override_secure_headers_request_config(request, config)
      request.env[SECURE_HEADERS_CONFIG] = config
    end

    # Private: determines which headers are applicable to a given request.
    #
    # Returns a list of classes whose corresponding header values are valid for
    # this request.
    def header_classes_for(request)
      if request.scheme == HTTPS
        ALL_HEADER_CLASSES
      else
        HTTP_HEADER_CLASSES
      end
    end

    # Private: do the heavy lifting of converting a configuration object
    # to a hash of headers valid for this request.
    #
    # Returns a hash of header names / values.
    def build_headers(config, request)
      header_classes_for(request).each_with_object({}) do |klass, hash|
        header_config = if config
          config.fetch(klass::CONFIG_KEY)
        end

        header_name, value = if klass == CSP
          make_header(klass, header_config, request.user_agent)
        else
          make_header(klass, header_config)
        end
        hash[header_name] = value if value
      end
    end

    # Private: takes a precomputed hash of headers and returns the Headers
    # customized for the request.
    #
    # Returns a hash of header names / values valid for a given request.
    def use_cached_headers(default_headers, request)
      header_classes_for(request).each_with_object({}) do |klass, hash|
        if default_header = default_headers[klass::CONFIG_KEY]
          header_name, value = if klass == CSP
            default_csp_header_for_ua(default_header, request)
          else
            default_header
          end
          hash[header_name] = value
        end
      end
    end

    # Private: Retreives the config for a given header type:
    #
    # Checks to see if there is an override for this request, then
    # Checks to see if a named override is used for this request, then
    # Falls back to the global config
    def config_for(request)
      request.env[SECURE_HEADERS_CONFIG] ||
        Configuration.get(Configuration::DEFAULT_CONFIG)
    end

    # Private: chooses the applicable CSP header for the provided user agent.
    #
    # headers - a hash of header_config_key => [header_name, header_value]
    #
    # Returns a CSP [header, value] array
    def default_csp_header_for_ua(headers, request)
      family = UserAgent.parse(request.user_agent).browser
      if CSP::VARIATIONS.key?(family)
        headers[family]
      else
        headers[CSP::OTHER]
      end
    end

    # Private: optionally build a header with a given configure
    #
    # klass - corresponding Class for a given header
    # config - A string, symbol, or hash config for the header
    # user_agent - A string representing the UA  (only used for CSP feature sniffing)
    #
    # Returns a 2 element array [header_name, header_value] or nil if config
    # is OPT_OUT
    def make_header(klass, header_config, user_agent = nil)
      unless header_config == OPT_OUT
        if klass == CSP
          klass.make_header(header_config, user_agent)
        else
          klass.make_header(header_config)
        end
      end
    end
  end

  # These methods are mixed into controllers and delegate to the class method
  # with the same name.
  def use_secure_headers_override(name)
    SecureHeaders.use_secure_headers_override(request, name)
  end

  def content_security_policy_script_nonce
    SecureHeaders.content_security_policy_script_nonce(request)
  end

  def content_security_policy_style_nonce
    SecureHeaders.content_security_policy_style_nonce(request)
  end

  def opt_out_of_header(header_key)
    SecureHeaders.opt_out_of_header(request, header_key)
  end

  def append_content_security_policy_directives(additions)
    SecureHeaders.append_content_security_policy_directives(request, additions)
  end

  def override_content_security_policy_directives(additions)
    SecureHeaders.override_content_security_policy_directives(request, additions)
  end

  def override_x_frame_options(value)
    SecureHeaders.override_x_frame_options(request, value)
  end
end
