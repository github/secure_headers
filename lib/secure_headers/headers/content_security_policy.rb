require 'uri'
require 'base64'
require 'securerandom'
require 'user_agent_parser'
require 'json'

module SecureHeaders
  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicy < Header
    module Constants
      DEFAULT_CSP_HEADER = "default-src https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https: about: javascript:; img-src data:"
      HEADER_NAME = "Content-Security-Policy"
      NONCE_KEY = "secure_headers.content_security_policy_nonce"
      DATA = "data:"
      SELF = "'self'"
      NONE = "'none'"
      STAR = "*"
      UNSAFE_INLINE = "'unsafe-inline'"
      UNSAFE_EVAL = "'unsafe-eval'"

      SOURCE_VALUES = [
        STAR,
        DATA,
        SELF,
        NONE,
        UNSAFE_EVAL,
        UNSAFE_INLINE
      ]

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
      META_CONFIG = [:tag_report_uri, :app_name, :enforce]
      CONFIG_KEY = :csp
      STAR_REGEXP = Regexp.new(Regexp.escape(STAR))
      NONCE_REGEXP = Regexp.new(/nonce-/)
    end
    include Constants

    class << self
      def symbol_to_hyphen_case sym
        sym.to_s.gsub('_', '-')
      end

      def validate_config(config)
        return if config.nil?
        raise ContentSecurityPolicyConfigError.new(":default_src is required") unless config[:default_src]
        config.each do |key, value|
          case key
          when :tag_report_uri, :enforce, :block_all_mixed_content
            unless value.is_a?(TrueClass) || value.is_a?(FalseClass)
              raise ContentSecurityPolicyConfigError.new("#{key} must be a boolean value")
            end
          when :app_name, :reflected_xss
            unless value.is_a?(String)
              raise ContentSecurityPolicyConfigError.new("#{key} must be a string value")
            end
          else
            unless ContentSecurityPolicy::ALL_DIRECTIVES.include?(key)
              raise ContentSecurityPolicyConfigError.new("Unknown directive #{key}")
            end
            unless value.is_a?(Array) && value.all? {|v| v.is_a?(String)}
              raise ContentSecurityPolicyConfigError.new("#{key} must be an array of strings")
            end
          end
        end
      end
    end

    # :report used to determine what :ssl_request, :ua, and :request_uri are set to
    def initialize(config=nil)
      return unless config

      @ua = config.delete(:ua)
      @tag_report_uri = !!config.delete(:tag_report_uri)
      @app_name = config.delete(:app_name)
      @enforce = !!config.delete(:enforce)
      @config = config

      # tag the report-uri(s)
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

    # ensures defualt_src is first and block-all-mixed-content / report_uri are last
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
      directive_config = @config[key].uniq
      value = if directive_config.include?(STAR)
        STAR
      else
        directive_config.reject! { |value| value == NONE} if directive_config.length > 1
        directive_config.reject! { |value| value =~ NONCE_REGEXP } unless supports_nonces?
        dedup_source_list(directive_config).join(" ")
      end
      [self.class.symbol_to_hyphen_case(key), value].join(" ")
    end

    def dedup_source_list(sources)
      sources = sources.uniq
      wild_sources = sources.select { |source| source =~ STAR_REGEXP }

      if wild_sources.any?
        sources.reject do |source|
          !wild_sources.include?(source) &&
            wild_sources.any? { |pattern| File.fnmatch(pattern, source) }
        end
      else
        sources
      end
    end

    def strip_unsupported_directives
      @config.select! { |key, _| supported_directives.include?(key) }
    end

    def supported_directives
      @supported_directives ||= case UserAgentParser.parse(@ua).family
      when "Chrome", "Opera"
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
