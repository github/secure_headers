require 'uri'
require 'base64'
require 'securerandom'
require 'user_agent_parser'
require 'json'
require 'pry'

module SecureHeaders
  class ContentSecurityPolicyBuildError < StandardError; end
  class ContentSecurityPolicy < Header
    module Constants
      DEFAULT_CSP_HEADER = "default-src https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https: about: javascript:; img-src data:"
      HEADER_NAME = "Content-Security-Policy"
      ENV_KEY = 'secure_headers.content_security_policy'

      DIRECTIVES_1_0 = [
        :default_src,
        :connect_src,
        :font_src,
        :frame_src,
        :img_src,
        :media_src,
        :object_src,
        :sandbox,
        :script_src,
        :style_src,
        :report_uri
      ].freeze

      DIRECTIVES_2_0 = [
        DIRECTIVES_1_0,
        :base_url,
        :child_src,
        :form_action,
        :frame_ancestors,
        :plugin_types
      ].flatten.freeze


      # All the directives currently under consideration for CSP level 3.
      # https://w3c.github.io/webappsec/specs/CSP2/
      DIRECTIVES_3_0 = [
        DIRECTIVES_2_0,
        :manifest_src,
        :reflected_xss
      ].flatten.freeze

      # All the directives that are not currently in a formal spec, but have
      # been implemented somewhere.
      DIRECTIVES_DRAFT = [
        :block_all_mixed_content,
      ].freeze

      SAFARI_DIRECTIVES = DIRECTIVES_1_0

      FIREFOX_UNSUPPORTED_DIRECTIVES = [
        :block_all_mixed_content,
        :child_src,
        :plugin_types
      ].freeze

      FIREFOX_DIRECTIVES = (
        DIRECTIVES_2_0 - FIREFOX_UNSUPPORTED_DIRECTIVES
      ).freeze

      CHROME_DIRECTIVES = (
        DIRECTIVES_2_0 + DIRECTIVES_DRAFT
      ).freeze

      ALL_DIRECTIVES = DIRECTIVES_1_0 + DIRECTIVES_2_0 + DIRECTIVES_3_0 + DIRECTIVES_DRAFT
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
      @http_additions = config.delete(:http_additions)
      @app_name = config.delete(:app_name)
      @enforce = !!config.delete(:enforce)
      @disable_img_src_data_uri = !!config.delete(:disable_img_src_data_uri)
      @tag_report_uri = !!config.delete(:tag_report_uri)
      @script_hashes = config.delete(:script_hashes) || []

      # Config values can be string, array, or lamdba values
      @config = config.inject({}) do |hash, (key, value)|
        config_val = value.respond_to?(:call) ? value.call(@controller) : value
        if ContentSecurityPolicy::ALL_DIRECTIVES.include?(key.to_sym) # directives need to be normalized to arrays of strings
          config_val = config_val.split if config_val.is_a? String
          if config_val.is_a?(Array)
            config_val = config_val.map do |val|
              translate_dir_value(val)
            end.flatten.uniq
          end
        else
          raise ArgumentError.new("Unknown directive supplied: #{key}")
        end


        hash[key] = config_val
        hash
      end

      add_script_hashes if @script_hashes.any?
      puts @config
      strip_unsupported_directives
      puts @config
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
      out = @config.inject({}) do |hash, (key, value)|
        hash[key.to_s.gsub(/(\w+)_(\w+)/, "\\1-\\2")] = value
        hash
      end
      puts out
      out.to_json
    end

    def self.from_json(*json_configs)
      json_configs.inject({}) do |combined_config, one_config|
        config = JSON.parse(one_config).inject({}) do |hash, (key, value)|
          hash[key.gsub(/(\w+)-(\w+)/, "\\1_\\2").to_sym] = value
          hash
        end
        combined_config.merge(config) do |_, lhs, rhs|
          lhs | rhs
        end
      end
    end

    private

    def add_script_hashes
      @config[:script_src] << @script_hashes.map {|hash| "'#{hash}'"} << ["'unsafe-inline'"]
    end

    def build_value
      raise "Expected to find default_src directive value" unless @config[:default_src]
      append_http_additions unless ssl_request?
      generic_directives
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
        if supports_nonces?
          self.class.set_nonce(@controller, nonce)
          ["'nonce-#{nonce}'", "'unsafe-inline'"]
        else
          "'unsafe-inline'"
        end
      else
        val
      end
    end

    def generic_directives
      header_value = ''
      data_uri = @disable_img_src_data_uri ? [] : ["data:"]
      if @config[:img_src]
        @config[:img_src] = @config[:img_src] + data_uri unless @config[:img_src].include?('data:')
      else
        @config[:img_src] = @config[:default_src] + data_uri
      end

      ALL_DIRECTIVES.each do |directive_name|
        header_value += build_directive(directive_name) if @config[directive_name]
      end

      header_value
    end

    def build_directive(key)
      "#{self.class.symbol_to_hyphen_case(key)} #{@config[key].join(" ")}; "
    end

    def strip_unsupported_directives
      @config.select! { |key, _| supported_directives.include?(key) }
    end

    def supported_directives
      @supported_directives ||= case UserAgentParser.parse(@ua).family
      when "Chrome"
        CHROME_DIRECTIVES
      when "Safari"
        SAFARI_DIRECTIVES
      when "Firefox"
        FIREFOX_DIRECTIVES
      else
        DIRECTIVES_1_0
      end
    end

    def supports_nonces?
      parsed_ua = UserAgentParser.parse(@ua)
      ["Chrome", "Opera", "Firefox"].include?(parsed_ua.family)
    end
  end
end
