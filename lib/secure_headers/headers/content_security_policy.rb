require 'uri'
require 'base64'
require 'securerandom'
require 'user_agent_parser'
require 'json'

module SecureHeaders
  class ContentSecurityPolicyBuildError < StandardError; end
  class ContentSecurityPolicy < Header
    module Constants
      DEFAULT_CSP_HEADER = "default-src https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https: about: javascript:; img-src data:"
      HEADER_NAME = "Content-Security-Policy"
      ENV_KEY = 'secure_headers.content_security_policy'
      DIRECTIVES = [
        :default_src,
        :connect_src,
        :font_src,
        :frame_src,
        :img_src,
        :media_src,
        :object_src,
        :script_src,
        :style_src,
        :base_uri,
        :child_src,
        :form_action,
        :frame_ancestors,
        :plugin_types
      ]

      OTHER = [
        :report_uri
      ]

      ALL_DIRECTIVES = DIRECTIVES + OTHER
      CONFIG_KEY = :csp
    end

    include Constants

    attr_reader :ssl_request
    alias :ssl_request? :ssl_request

    class << self
      def generate_nonce
        SecureRandom.base64(32).chomp
      end

      def set_nonce(controller, nonce = generate_nonce)
        controller.instance_variable_set(:@content_security_policy_nonce, nonce)
      end

      def add_to_env(request, controller, config)
        set_nonce(controller)
        options = options_from_request(request).merge(:controller => controller)
        request.env[Constants::ENV_KEY] = {
          :config => config,
          :options => options,
        }
      end

      def options_from_request(request)
        {
          :ssl => request.ssl?,
          :ua => request.env['HTTP_USER_AGENT'],
          :request_uri => request_uri_from_request(request),
        }
      end

      def request_uri_from_request(request)
        if request.respond_to?(:original_url)
          # rails 3.1+
          request.original_url
        else
          # rails 2/3.0
          request.url
        end
      end

      def symbol_to_hyphen_case sym
        sym.to_s.gsub('_', '-')
      end
    end

    # +options+ param contains
    # :controller used for setting instance variables for nonces/hashes
    # :ssl_request used to determine if http_additions should be used
    # :ua the user agent (or just use Firefox/Chrome/MSIE/etc)
    #
    # :report used to determine what :ssl_request, :ua, and :request_uri are set to
    def initialize(config=nil, options={})
      return unless config

      if options[:request]
        options = options.merge(self.class.options_from_request(options[:request]))
      end

      @controller = options[:controller]
      @ua = options[:ua]
      @ssl_request = !!options.delete(:ssl)
      @request_uri = options.delete(:request_uri)

      puts config

      # Config values can be string, array, or lamdba values
      @config = config.inject({}) do |hash, (key, value)|
        config_val = value.respond_to?(:call) ? value.call(@controller) : value

        if DIRECTIVES.include?(key) # directives need to be normalized to arrays of strings
          config_val = config_val.split if config_val.is_a? String
          if config_val.is_a?(Array)
            # if 'none' is supplied with additional values, assume the override was
            # intentional and remove any 'none's
            if config_val.size > 1
              config_val.reject! { |value| value == "'none'" }
            end
            config_val = config_val.map do |val|
              translate_dir_value(val)
            end.flatten.uniq
          end
        end

        hash[key.to_s] = config_val
        hash
      end

      puts @config

      @http_additions = @config.delete(:http_additions)
      @app_name = @config.delete(:app_name)
      @report_uri = @config.delete(:report_uri)
      @enforce = !!@config.delete(:enforce)
      @disable_img_src_data_uri = !!@config.delete(:disable_img_src_data_uri)
      @tag_report_uri = !!@config.delete(:tag_report_uri)
      @script_hashes = @config.delete(:script_hashes) || []

      add_script_hashes if @script_hashes.any?
    end

    ##
    # Return or initialize the nonce value used for this header.
    # If a reference to a controller is passed in the config, this method
    # will check if a nonce has already been set and use it.
    def nonce
      @nonce ||= @controller.instance_variable_get(:@content_security_policy_nonce) || self.class.generate_nonce
    end

    ##
    # Returns the name to use for the header. Either "Content-Security-Policy" or
    # "Content-Security-Policy-Report-Only"
    def name
      base = HEADER_NAME
      if !@enforce
        base += "-Report-Only"
      end
      base
    end

    ##
    # Return the value of the CSP header
    def value
      return @config if @config.is_a?(String)
      if @config
        build_value
      else
        DEFAULT_CSP_HEADER
      end
    end

    def to_json
      build_value
      @config.to_json.gsub(/(\w+)_src/, "\\1-src")
    end

    def self.from_json(*json_configs)
      json_configs.inject({}) do |combined_config, one_config|
        one_config = one_config.gsub(/(\w+)-src/, "\\1_src")
        config = JSON.parse(one_config, :symbolize_names => true)
        combined_config.merge(config) do |_, lhs, rhs|
          lhs | rhs
        end
      end
    end

    private

    def add_script_hashes
      @config["script_src"] << @script_hashes.map {|hash| "'#{hash}'"} << ["'unsafe-inline'"]
    end

    def build_value
      binding.pry
      raise "Expected to find default_src directive value" unless @config["default_src"]
      append_http_additions unless ssl_request?
      header_value = [
        generic_directives,
        report_uri_directive
      ].join.strip
    end

    def append_http_additions
      return unless @http_additions
      @http_additions.each do |k, v|
        @config[k] ||= []
        @config[k] << v
      end
    end

    def translate_dir_value val
      if %w{inline eval}.include?(val)
        warn "[DEPRECATION] using inline/eval may not be supported in the future. Instead use 'unsafe-inline'/'unsafe-eval' instead."
        val == 'inline' ? "'unsafe-inline'" : "'unsafe-eval'"
      elsif %{self none}.include?(val)
        warn "[DEPRECATION] using self/none may not be supported in the future. Instead use 'self'/'none' instead."
        "'#{val}'"
      elsif val == 'nonce'
        if supports_nonces?(@ua)
          self.class.set_nonce(@controller, nonce)
          ["'nonce-#{nonce}'", "'unsafe-inline'"]
        else
          "'unsafe-inline'"
        end
      else
        val
      end
    end

    def report_uri_directive
      return '' if @report_uri.nil?

      if @report_uri.start_with?('//')
        @report_uri = if @ssl_request
                        "https:" + @report_uri
                      else
                        "http:" + @report_uri
                      end
      end

      if @tag_report_uri
        @report_uri = "#{@report_uri}?enforce=#{@enforce}"
        @report_uri += "&app_name=#{@app_name}" if @app_name
      end

      "report-uri #{@report_uri};"
    end

    def generic_directives
      header_value = ''
      data_uri = @disable_img_src_data_uri ? [] : ["data:"]
      if @config["img_src"]
        @config["img_src"] = @config["img_src"] + data_uri unless @config["img_src"].include?('data:')
      else
        binding.pry
        @config["img_src"] = @config["default_src"] + data_uri
      end

      DIRECTIVES.each do |directive_name|
        header_value += build_directive(directive_name) if @config[directive_name]
      end

      header_value
    end

    def build_directive(key)
      "#{self.class.symbol_to_hyphen_case(key)} #{@config[key].join(" ")}; "
    end

    def supports_nonces?(user_agent)
      parsed_ua = UserAgentParser.parse(user_agent)
      ["Chrome", "Opera", "Firefox"].include?(parsed_ua.family)
    end
  end
end
