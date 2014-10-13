require 'yaml'

module SecureHeaders
  module Configuration
    class << self
      attr_accessor :hsts, :x_frame_options, :x_content_type_options,
        :x_xss_protection, :csp, :x_download_options

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
    attr_writer :script_hashes
    def secure_headers_options
      if @secure_headers_options
        @secure_headers_options
      elsif superclass.respond_to?(:secure_headers_options) # stop at application_controller
        superclass.secure_headers_options
      else
        {}
      end
    end

    def script_hashes
      if @script_hashes
        @script_hashes
      elsif superclass.respond_to?(:script_hashes) # stop at application_controller
        superclass.script_hashes
      else
        {}
      end
    end

    def ensure_security_headers options = {}
      begin
        self.script_hashes = ::YAML::load_file('config/script_hashes.yml')
      rescue Errno::ENOENT => e
        puts "WARN: no script hash file."
      end
      self.secure_headers_options = options
      before_filter :prep_script_hash
      before_filter :set_hsts_header
      before_filter :set_x_frame_options_header
      before_filter :set_csp_header
      before_filter :set_x_xss_protection_header
      before_filter :set_x_content_type_options_header
      before_filter :set_x_download_options_header
    end

    # we can't use ||= because I'm overloading false => disable, nil => default
    # both of which trigger the conditional assignment
    def options_for(type, options)
      options.nil? ? ::SecureHeaders::Configuration.send(type) : options
    end
  end

  module InstanceMethods
    # Re-added for backwards compat.
    def set_security_headers(options = self.class.secure_headers_options)
      set_csp_header(request, options[:csp])
      set_hsts_header(options[:hsts])
      set_x_frame_options_header(options[:x_frame_options])
      set_x_xss_protection_header(options[:x_xss_protection])
      set_x_content_type_options_header(options[:x_content_type_options])
      set_x_download_options_header(options[:x_download_options])
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
      matching_hashes = self.class.script_hashes[payload[:identifier].gsub(Rails.root.to_s + "/", "")]
      if matching_hashes
        request.env['script_hashes'] = ((request.env['script_hashes'] || []) << matching_hashes).flatten
      end
    end

    # backwards compatibility jank, to be removed in 1.0. Old API required a request
    # object when it didn't really need to.
    # set_csp_header - uses the request accessor and SecureHeader::Configuration settings
    # set_csp_header(+Rack::Request+) - uses the parameter and and SecureHeader::Configuration settings
    # set_csp_header(+Hash+) - uses the request accessor and options from parameters
    # set_csp_header(+Rack::Request+, +Hash+)
    def set_csp_header(req = nil, options=nil)
      # hack to help generating headers statically
      if req.is_a?(Hash)
        options = req
      end

      options = self.class.secure_headers_options[:csp] if options.nil?
      options = self.class.options_for :csp, options

      return if options == false

      csp_header = ContentSecurityPolicy.new(options, :request => request, :controller => self)
      set_header(csp_header, :save_to_env => true)
      if options && options[:experimental] && options[:enforce]
        experimental_header = ContentSecurityPolicy.new(options, :experimental => true, :request => request, :controller => self)
        set_header(experimental_header, :save_to_env => true)
      end
    end

    def set_x_frame_options_header(options=self.class.secure_headers_options[:x_frame_options])
      set_a_header(:x_frame_options, XFrameOptions, options)
    end

    def set_x_content_type_options_header(options=self.class.secure_headers_options[:x_content_type_options])
      set_a_header(:x_content_type_options, XContentTypeOptions, options)
    end

    def set_x_xss_protection_header(options=self.class.secure_headers_options[:x_xss_protection])
      set_a_header(:x_xss_protection, XXssProtection, options)
    end

    def set_hsts_header(options=self.class.secure_headers_options[:hsts])
      return unless request.ssl?
      set_a_header(:hsts, StrictTransportSecurity, options)
    end

    def set_x_download_options_header(options=self.class.secure_headers_options[:x_download_options])
      set_a_header(:x_download_options, XDownloadOptions, options)
    end

    private

    def set_a_header(name, klass, options=nil)
      options = self.class.options_for name, options
      return if options == false

      header = klass.new(options)
      set_header(header)
    end

    def set_header(header, options={})
      if options[:save_to_env]
        request.env[header.name] = header
      end
      response.headers[header.name] = header.value
    end
  end
end


require "secure_headers/version"
require "secure_headers/script_hash"
require "secure_headers/header"
require "secure_headers/headers/content_security_policy"
require "secure_headers/headers/x_frame_options"
require "secure_headers/headers/strict_transport_security"
require "secure_headers/headers/x_xss_protection"
require "secure_headers/headers/x_content_type_options"
require "secure_headers/headers/x_download_options"
require "secure_headers/railtie"
