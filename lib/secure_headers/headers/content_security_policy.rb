require 'uri'
require 'base64'
require 'securerandom'
require 'user_agent_parser'
require 'json'

module SecureHeaders
  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicy < Header
    DEFAULT_CSP_HEADER = "default-src https:;".freeze
    HEADER_NAME = "Content-Security-Policy".freeze
    DATA = "data:".freeze
    SELF = "'self'".freeze
    NONE = "'none'".freeze
    STAR = "*".freeze
    UNSAFE_INLINE = "'unsafe-inline'".freeze
    UNSAFE_EVAL = "'unsafe-eval'".freeze

    SOURCE_VALUES = [
      STAR,
      DATA,
      SELF,
      NONE,
      UNSAFE_EVAL,
      UNSAFE_INLINE
    ].freeze

    # leftover deprecated values that will be in common use upon upgrading.
    DEPRECATED_SOURCE_VALUES = [SELF, NONE, UNSAFE_EVAL, UNSAFE_INLINE, "inline", "eval"].map { |value| value.gsub("'", "")}.freeze

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

    DIRECTIVE_VALUE_TYPES = {
      BASE_URI                => :source_list,
      BLOCK_ALL_MIXED_CONTENT => :boolean,
      CHILD_SRC               => :source_list,
      CONNECT_SRC             => :source_list,
      DEFAULT_SRC             => :source_list,
      FONT_SRC                => :source_list,
      FORM_ACTION             => :source_list,
      FRAME_ANCESTORS         => :source_list,
      FRAME_SRC               => :source_list,
      IMG_SRC                 => :source_list,
      MANIFEST_SRC            => :source_list,
      MEDIA_SRC               => :source_list,
      OBJECT_SRC              => :source_list,
      PLUGIN_TYPES            => :source_list,
      REFLECTED_XSS           => :string,
      REPORT_URI              => :source_list,
      SANDBOX                 => :string,
      SCRIPT_SRC              => :source_list,
      STYLE_SRC               => :source_list
    }.freeze

    CONFIG_KEY = :csp
    STAR_REGEXP = Regexp.new(Regexp.escape(STAR))
    NONCE_REGEXP = /\A'nonce-/
    HASH_REGEXP = /\A'sha/
    HTTP_SCHEME_REGEX = %r(\Ahttps?://)

    class << self
      def make_header(config)
        validate_config!(config) if validate_config?
        header = new(config)
        [header.name, header.value]
      end

      def symbol_to_hyphen_case sym
        sym.to_s.gsub('_', '-')
      end

      def boolean?(value)
        value.is_a?(TrueClass) || value.is_a?(FalseClass)
      end

      def validate_config!(config)
        return if config.nil? || config == SecureHeaders::OPT_OUT
        raise ContentSecurityPolicyConfigError.new(":default_src is required") unless config[:default_src]
        config.each do |key, value|
          case ContentSecurityPolicy::DIRECTIVE_VALUE_TYPES[key]
          when :boolean
            unless boolean?(value)
              raise ContentSecurityPolicyConfigError.new("#{key} must be a boolean value")
            end
          when :string
            unless value.is_a?(String)
              raise ContentSecurityPolicyConfigError.new("#{key} Must be a string. Found #{config.class}: #{config} value")
            end
          else
            if key == :enforce
              raise ContentSecurityPolicyConfigError.new("#{key} must be a boolean value") unless boolean?(value) || value.nil?
            elsif key == :ua
              raise ContentSecurityPolicyConfigError.new("#{key} must be a string value") unless value.is_a?(String) || value.nil?
            else
              unless ContentSecurityPolicy::ALL_DIRECTIVES.include?(key)
                raise ContentSecurityPolicyConfigError.new("Unknown directive #{key}")
              end
              unless value.is_a?(Array) && value.all? {|v| v.is_a?(String)}
                raise ContentSecurityPolicyConfigError.new("#{key} must be an array of strings")
              end

              value.each do |source_expression|
                if ContentSecurityPolicy::DEPRECATED_SOURCE_VALUES.include?(source_expression)
                  raise ContentSecurityPolicyConfigError.new("#{key} contains an invalid keyword source (#{source_expression}). This value must be single quoted.")
                end
              end
            end
          end
        end
      end
    end

    # :report used to determine what :ssl_request, :ua, and :request_uri are set to
    def initialize(config=nil)
      return unless config
      @config = config
      @parsed_ua = UserAgentParser.parse(@config.delete(:ua))
      @enforce = !!@config.delete(:enforce)
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

    # ensures defualt_src is first and report_uri are last
    def build_value
      header_value = [build_directive(DEFAULT_SRC)]

      directives = filter_unsupported_directives(ALL_DIRECTIVES - [DEFAULT_SRC, REPORT_URI])

      directives.select { |directive| @config[directive]}.each do |directive_name|
        header_value << case DIRECTIVE_VALUE_TYPES[directive_name]
        when :boolean
          self.class.symbol_to_hyphen_case(directive_name)
        when :string
          [self.class.symbol_to_hyphen_case(directive_name), @config[directive_name]].join(" ")
        else
           build_directive(directive_name)
        end
      end

      header_value << build_directive(REPORT_URI) if @config[REPORT_URI]

      header_value.join("; ")
    end

    # Join the unique values. Discard 'none' if a directive has additional config, discard
    # addtional config if directive has *
    def build_directive(directive_name)
      source_list = @config[directive_name].compact
      value = if source_list.include?(STAR)
        # Discard trailing entries since * accomplishes the same.
        STAR
      else
        # Discard any 'none' values if more directives are supplied since none may override values.
        source_list.reject! { |value| value == NONE} if source_list.length > 1
        # Discard nonces/hash for browsers that do not support them
        source_list.reject! do |value|
          value =~ NONCE_REGEXP && !supports_nonces? ||
          value =~ HASH_REGEXP && !supports_hashes?
        end

        # remove schemes and dedup source expressions
        dedup_source_list(strip_source_schemes(source_list)).join(" ")
      end
      [self.class.symbol_to_hyphen_case(directive_name), value].join(" ")
    end

    # Removes duplicates and sources that already match an existing wild card.
    # Basically cargo culted from GitHub :P
    def dedup_source_list(sources)
      wild_sources = sources.select { |source| source =~ STAR_REGEXP }

      if wild_sources.any?
        sources.reject do |source|
          !wild_sources.include?(source) &&
            wild_sources.any? { |pattern| File.fnmatch(pattern, source) }
        end
      else
        sources
      end.uniq
    end

    def filter_unsupported_directives(directives)
      directives.select { |key| supported_directives.include?(key) }
    end

    # Save bytes, discourages mixed content.
    # Basically cargo culted from GitHub :P
    def strip_source_schemes(source_list)
      source_list.map { |source_expression| source_expression.sub(HTTP_SCHEME_REGEX, "") }
    end

    def supported_directives
      @supported_directives ||= case @parsed_ua.family
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

    def supports_hashes?
      ["Chrome", "Opera", "Firefox"].include?(@parsed_ua.family)
    end

    def supports_nonces?
      ["Chrome", "Opera", "Firefox"].include?(@parsed_ua.family)
    end
  end
end
