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

    attr_accessor :secure_headers_options

    def ensure_security_headers options = {}, *args
      self.secure_headers_options = options
      before_filter :set_security_headers
    end

    # we can't use ||= because I'm overloading false => disable, nil => default
    # both of which trigger the conditional assignment
    def options_for(type, options)
      options.nil? ? ::SecureHeaders::Configuration.send(type) : options
    end
  end

  module InstanceMethods
    def set_security_headers(options = self.class.secure_headers_options || {})
      brwsr = Brwsr::Browser.new(:ua => request.env['HTTP_USER_AGENT'])
      set_hsts_header(options[:hsts]) if request.ssl?
      set_x_frame_options_header(options[:x_frame_options])
      set_csp_header(request, options[:csp]) unless broken_implementation?(brwsr)
      set_x_xss_protection_header(options[:x_xss_protection])
      if brwsr.ie?
        set_x_content_type_options_header(options[:x_content_type_options])
      end
    end

    def set_csp_header(request, options=nil)
      options = self.class.options_for :csp, options
      return if options == false

      header = ContentSecurityPolicy.build(request, options)
      set_header(header.name, header.value)
    end

    def set_a_header(name, klass, options=nil)
      options = self.class.options_for name, options
      return if options == false

      header = klass.new(options)
      set_header(header.name, header.value)
    end

    def set_x_frame_options_header(options=nil)
      set_a_header(:x_frame_options, XFrameOptions, options)
    end

    def set_x_content_type_options_header(options=nil)
      set_a_header(:x_content_type_options, XContentTypeOptions, options)
    end

    def set_x_xss_protection_header(options=nil)
      set_a_header(:x_xss_protection, XXssProtection, options)
    end

    def set_hsts_header(options=nil)
      set_a_header(:hsts, StrictTransportSecurity, options)
    end

    def set_header(name, value)
      response.headers[name] = value
    end

    private

    def broken_implementation?(browser)
      #IOS 5 sometimes refuses to load external resources even when whitelisted with CSP
      return browser.ios5?
    end
  end
end


require "secure_headers/version"
require "secure_headers/headers/content_security_policy"
require "secure_headers/headers/firefox_content_security_policy"
require "secure_headers/headers/webkit_content_security_policy"
require "secure_headers/headers/x_frame_options"
require "secure_headers/headers/strict_transport_security"
require "secure_headers/headers/x_xss_protection"
require "secure_headers/headers/x_content_type_options"
require "secure_headers/railtie"
require "brwsr"
