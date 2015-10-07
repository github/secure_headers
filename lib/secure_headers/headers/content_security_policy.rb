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
      DATA = "data:"
      SELF = "'self'"
      NONE = "'none'"
      UNSAFE_INLINE = "'unsafe-inline'"
      UNSAFE_EVAL = "'unsafe-eval'"

      DEFAULT_SRC = :default_src
      CONNECT_SRC = :connect_src
      FONT_SRC = :font_src
      FRAME_SRC = :frame_src
      IMG_SRC = :img_src
      MEDIA_SRC = :media_src
      OBJECT_SRC = :object_src
      SANDBOX = :sandbox
      SCRIPT_SRC = :script_src
      STYLE_SRC = :style_src
      REPORT_URI = :report_uri

      DIRECTIVES_1_0 = [
        DEFAULT_SRC,
        CONNECT_SRC,
        FONT_SRC,
        FRAME_SRC,
        IMG_SRC,
        MEDIA_SRC,
        OBJECT_SRC,
        SANDBOX,
        SCRIPT_SRC,
        STYLE_SRC,
        REPORT_URI
      ].freeze


      BASE_URI = :base_uri
      CHILD_SRC = :child_src
      FORM_ACTION = :form_action
      FRAME_ANCESTORS = :frame_ancestors
      PLUGIN_TYPES = :plugin_types

      DIRECTIVES_2_0 = [
        DIRECTIVES_1_0,
        BASE_URI,
        CHILD_SRC,
        FORM_ACTION,
        FRAME_ANCESTORS,
        PLUGIN_TYPES
      ].flatten.freeze


      # All the directives currently under consideration for CSP level 3.
      # https://w3c.github.io/webappsec/specs/CSP2/
      MANIFEST_SRC = :manifest_src
      REFLECTED_XSS = :reflected_xss
      DIRECTIVES_3_0 = [
        DIRECTIVES_2_0,
        MANIFEST_SRC,
        REFLECTED_XSS
      ].flatten.freeze

      # All the directives that are not currently in a formal spec, but have
      # been implemented somewhere.
      BLOCK_ALL_MIXED_CONTENT = :block_all_mixed_content
      DIRECTIVES_DRAFT = [
        BLOCK_ALL_MIXED_CONTENT
      ].freeze

      SAFARI_DIRECTIVES = DIRECTIVES_1_0

      FIREFOX_UNSUPPORTED_DIRECTIVES = [
        BLOCK_ALL_MIXED_CONTENT,
        CHILD_SRC,
        PLUGIN_TYPES
      ].freeze

      FIREFOX_DIRECTIVES = (
        DIRECTIVES_2_0 - FIREFOX_UNSUPPORTED_DIRECTIVES
      ).freeze

      CHROME_DIRECTIVES = (
        DIRECTIVES_2_0 + DIRECTIVES_DRAFT
      ).freeze

      ALL_DIRECTIVES = [DIRECTIVES_1_0 + DIRECTIVES_2_0 + DIRECTIVES_3_0 + DIRECTIVES_DRAFT].flatten.uniq.sort
      CONFIG_KEY = :csp
    end
    include Constants

    attr_reader :ssl_request
    alias :ssl_request? :ssl_request

    class << self
      def generate_nonce
        SecureRandom.base64(32).chomp
      end

      def get_nonce

      end

      def set_nonce(controller, nonce = generate_nonce)
        # controller.instance_variable_set(:@content_security_policy_nonce, nonce)
        # TODO set in ENV config too
      end

      def add_to_env(request, controller, config)

      end

      def symbol_to_hyphen_case sym
        sym.to_s.gsub('_', '-')
      end
    end

    # :report used to determine what :ssl_request, :ua, and :request_uri are set to
    def initialize(config=nil)
      return unless config

      @ua = config.delete(:ua)
      @tag_report_uri = !!config.delete(:tag_report_uri)
      @script_hashes = config.delete(:script_hashes) || []
      @app_name = config.delete(:app_name)
      @enforce = !!config.delete(:enforce)
      @config = config

      raise ArgumentError.new("Expected to find default_src directive value") unless @config[DEFAULT_SRC]

      # tag the report-uri
      if @config[REPORT_URI] && @tag_report_uri
        @config[REPORT_URI] = @config[REPORT_URI].map do |report_uri|
          report_uri = "#{report_uri}?enforce=#{@enforce}"
          report_uri += "&app_name=#{@app_name}" if @app_name
          report_uri
        end
      end

      strip_unsupported_directives
    end

    ##
    # Return or initialize the nonce value used for this header.
    # If a reference to a controller is passed in the config, this method
    # will check if a nonce has already been set and use it.
    def nonce
      # @nonce ||= @controller.instance_variable_get(:@content_security_policy_nonce) || self.class.generate_nonce
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
      @value ||= if @config
        build_value
      else
        DEFAULT_CSP_HEADER
      end
    end

    def to_json
      @config.inject({}) do |hash, (key, value)|
        if ALL_DIRECTIVES.include?(key)
          hash[key.to_s.gsub("_", "-")] = value
        end
        hash
      end.to_json
    end

    def self.from_json(*json_configs)
      json_configs.inject({}) do |combined_config, one_config|
        config = JSON.parse(one_config).inject({}) do |hash, (key, value)|
          hash[key.gsub('-', '_').to_sym] = value
          hash
        end
        combined_config.merge(config) do |_, lhs, rhs|
          lhs | rhs
        end
      end
    end

    private

    # ensures defualt_src is first and report_uri is last
    def build_value
      header_value = [build_directive(DEFAULT_SRC)]

      (ALL_DIRECTIVES - [DEFAULT_SRC, REPORT_URI, BLOCK_ALL_MIXED_CONTENT]).each do |directive_name|
        if @config[directive_name]
          header_value << build_directive(directive_name)
        end
      end

      header_value << "block-all-mixed-content" if @config[BLOCK_ALL_MIXED_CONTENT]
      header_value << build_directive(REPORT_URI) if @config[REPORT_URI]

      header_value.join("; ")
    end

    # Join the unique values and discard 'none' if a directive has additional config.
    def build_directive(key)
      directive = @config[key].uniq
      directive.reject! { |value| value == NONE} if directive.length > 1
      "#{self.class.symbol_to_hyphen_case(key)} #{directive.join(" ")}"
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
