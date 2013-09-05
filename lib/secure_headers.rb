module SecureHeaders
  module Configuration
    class << self
      attr_accessor :hsts, :x_frame_options, :x_content_type_options,
        :x_xss_protection, :csp

      def configure &block
        instance_eval &block
      end
    end
  end

  class << self
    def append_features(base)
      base.module_eval do
        extend ClassMethods
        include InstanceMethods
      end
    end
  end

  module ClassMethods
    attr_writer :secure_headers_options
    def secure_headers_options
      if @secure_headers_options
        @secure_headers_options
      elsif superclass.respond_to?(:secure_headers_options) # stop at application_controller
        superclass.secure_headers_options
      else
        {}
      end
    end

    def ensure_security_headers options = {}
      self.secure_headers_options = options
      before_filter :set_hsts_header
      before_filter :set_x_frame_options_header
      before_filter :set_csp_header
      before_filter :set_x_xss_protection_header
      before_filter :set_x_content_type_options_header
    end

    # we can't use ||= because I'm overloading false => disable, nil => default
    # both of which trigger the conditional assignment
    def options_for(type, options)
      options.nil? ? ::SecureHeaders::Configuration.send(type) : options
    end
  end

  module InstanceMethods
    def brwsr
      @secure_headers_brwsr ||= Brwsr::Browser.new(:ua => request.env['HTTP_USER_AGENT'])
    end

    # backwards compatibility jank, to be removed in 1.0. Old API required a request
    # object when it didn't really need to.
    # set_csp_header - uses the request accessor and SecureHeader::Configuration settings
    # set_csp_header(+Rack::Request+) - uses the parameter and and SecureHeader::Configuration settings
    # set_csp_header(+Hash+) - uses the request accessor and options from parameters
    # set_csp_header(+Rack::Request+, +Hash+)
    def set_csp_header(req = nil, options=nil)
      return if api_request?
      return if request.xhr?
      return if broken_implementation?(brwsr)

      if req.is_a?(Hash)
        options = req
      elsif req
        @secure_headers_brwsr = Brwsr::Browser.new(:ua => req.env['HTTP_USER_AGENT'])
      end

      options = self.class.secure_headers_options[:csp] if options.nil?
      options = self.class.options_for :csp, options

      return if options == false

      csp_header = ContentSecurityPolicy.new(options, :request => request, :controller => self)
      set_header(csp_header)
      if options && options[:experimental] && options[:enforce]
        experimental_header = ContentSecurityPolicy.new(options, :experimental => true, :request => request, :controller => self)
        set_header(experimental_header)
      end
    end

    def set_x_frame_options_header(options=self.class.secure_headers_options[:x_frame_options])
      return if request.xhr?
      set_a_header(:x_frame_options, XFrameOptions, options)
    end

    def set_x_content_type_options_header(options=self.class.secure_headers_options[:x_content_type_options])
      return if api_request?
      return if request.xhr?
      return unless brwsr.ie? || brwsr.chrome?
      set_a_header(:x_content_type_options, XContentTypeOptions, options)
    end

    def set_x_xss_protection_header(options=self.class.secure_headers_options[:x_xss_protection])
      return if api_request?
      return if request.xhr?
      set_a_header(:x_xss_protection, XXssProtection, options)
    end

    def set_hsts_header(options=self.class.secure_headers_options[:hsts])
      return unless request.ssl?
      set_a_header(:hsts, StrictTransportSecurity, options)
    end

    private

    def api_request?
      ['json', 'xml', 'atom', 'atom+xml', 'rss', 'rss+xml'].include?(params[:format])
    end

    def set_a_header(name, klass, options=nil)
      options = self.class.options_for name, options
      return if options == false

      header = klass.new(options)
      set_header(header)
    end

    def set_header(name_or_header, value=nil)
      if name_or_header.is_a?(Header)
        header = name_or_header
        response.headers[header.name] = header.value
      else
        response.headers[name_or_header] = value
      end
    end

    def broken_implementation?(browser)
      return browser.ios5? || (browser.safari? && browser.version == '5')
    end
  end
end


require "secure_headers/version"
require "secure_headers/header"
require "secure_headers/headers/content_security_policy"
require "secure_headers/headers/content_security_policy/browser_strategy"
require "secure_headers/headers/content_security_policy/firefox_browser_strategy"
require "secure_headers/headers/content_security_policy/ie_browser_strategy"
require "secure_headers/headers/content_security_policy/standard_browser_strategy"
require "secure_headers/headers/x_frame_options"
require "secure_headers/headers/strict_transport_security"
require "secure_headers/headers/x_xss_protection"
require "secure_headers/headers/x_content_type_options"
require "secure_headers/railtie"
require "brwsr"
