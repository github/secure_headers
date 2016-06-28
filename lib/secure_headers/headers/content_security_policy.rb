require_relative 'policy_management'
require 'useragent'

module SecureHeaders
  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicy
    include PolicyManagement

    # constants to be used for version-specific UA sniffing
    VERSION_46 = ::UserAgent::Version.new("46")

    def initialize(config = nil, user_agent = OTHER)
      @config = Configuration.send(:deep_copy, config || DEFAULT_CONFIG)
      @parsed_ua = if user_agent.is_a?(UserAgent::Browsers::Base)
        user_agent
      else
        UserAgent.parse(user_agent)
      end
      normalize_child_frame_src
      @report_only = @config[:report_only]
      @preserve_schemes = @config[:preserve_schemes]
      @script_nonce = @config[:script_nonce]
      @style_nonce = @config[:style_nonce]
    end

    ##
    # Returns the name to use for the header. Either "Content-Security-Policy" or
    # "Content-Security-Policy-Report-Only"
    def name
      if @report_only
        REPORT_ONLY
      else
        HEADER_NAME
      end
    end

    ##
    # Return the value of the CSP header
    def value
      @value ||= if @config
        build_value
      else
        DEFAULT_VALUE
      end
    end

    private

    # frame-src is deprecated, child-src is being implemented. They are
    # very similar and in most cases, the same value can be used for both.
    def normalize_child_frame_src
      if @config[:frame_src] && @config[:child_src] && @config[:frame_src] != @config[:child_src]
        Kernel.warn("#{Kernel.caller.first}: [DEPRECATION] both :child_src and :frame_src supplied and do not match. This can lead to inconsistent behavior across browsers.")
      elsif @config[:frame_src]
        Kernel.warn("#{Kernel.caller.first}: [DEPRECATION] :frame_src is deprecated, use :child_src instead. Provided: #{@config[:frame_src]}.")
      end

      if supported_directives.include?(:child_src)
        @config[:child_src] = @config[:child_src] || @config[:frame_src]
      else
        @config[:frame_src] = @config[:frame_src] || @config[:child_src]
      end
    end

    # Private: converts the config object into a string representing a policy.
    # Places default-src at the first directive and report-uri as the last. All
    # others are presented in alphabetical order.
    #
    # Unsupported directives are filtered based on the user agent.
    #
    # Returns a content security policy header value.
    def build_value
      directives.map do |directive_name|
        case DIRECTIVE_VALUE_TYPES[directive_name]
        when :boolean
          symbol_to_hyphen_case(directive_name) if @config[directive_name]
        when :string
          [symbol_to_hyphen_case(directive_name), @config[directive_name]].join(" ")
        else
          build_directive(directive_name)
        end
      end.compact.join("; ")
    end

    # Private: builds a string that represents one directive in a minified form.
    #
    # directive_name - a symbol representing the various ALL_DIRECTIVES
    #
    # Returns a string representing a directive.
    def build_directive(directive)
      return if @config[directive].nil?

      source_list = @config[directive].compact
      return if source_list.empty?

      normalized_source_list = minify_source_list(directive, source_list)
      [symbol_to_hyphen_case(directive), normalized_source_list].join(" ")
    end

    # If a directive contains *, all other values are omitted.
    # If a directive contains 'none' but has other values, 'none' is ommitted.
    # Schemes are stripped (see http://www.w3.org/TR/CSP2/#match-source-expression)
    def minify_source_list(directive, source_list)
      if source_list.include?(STAR)
        keep_wildcard_sources(source_list)
      else
        populate_nonces!(directive, source_list)
        reject_all_values_if_none!(source_list)

        unless directive == REPORT_URI || @preserve_schemes
          strip_source_schemes!(source_list)
        end
        dedup_source_list(source_list).join(" ")
      end
    end

    # Discard trailing entries (excluding unsafe-*) since * accomplishes the same.
    def keep_wildcard_sources(source_list)
      source_list.select { |value| WILDCARD_SOURCES.include?(value) }
    end

    # Discard any 'none' values if more directives are supplied since none may override values.
    def reject_all_values_if_none!(source_list)
      source_list.reject! { |value| value == NONE } if source_list.length > 1
    end

    # Removes duplicates and sources that already match an existing wild card.
    #
    # e.g. *.github.com asdf.github.com becomes *.github.com
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

    # Private: append a nonce to the script/style directories if script_nonce
    # or style_nonce are provided.
    def populate_nonces!(directive, source_list)
      case directive
      when SCRIPT_SRC
        append_nonce(source_list, @script_nonce)
      when STYLE_SRC
        append_nonce(source_list, @style_nonce)
      end
    end

    # Private: adds a nonce or 'unsafe-inline' depending on browser support.
    # If a nonce is populated, inline content is assumed.
    #
    # While CSP is backward compatible in that a policy with a nonce will ignore
    # unsafe-inline, this is more concise.
    def append_nonce(source_list, nonce)
      if nonce
        if nonces_supported?
          source_list << "'nonce-#{nonce}'"
        else
          source_list << UNSAFE_INLINE
        end
      end
    end

    # Private: return the list of directives that are supported by the user agent,
    # starting with default-src and ending with report-uri.
    def directives
      [DEFAULT_SRC,
        BODY_DIRECTIVES.select { |key| supported_directives.include?(key) },
        REPORT_URI].flatten.select { |directive| @config.key?(directive) }
    end

    # Private: Remove scheme from source expressions.
    def strip_source_schemes!(source_list)
      source_list.map! { |source_expression| source_expression.sub(HTTP_SCHEME_REGEX, "") }
    end

    # Private: determine which directives are supported for the given user agent.
    #
    # Add UA-sniffing special casing here.
    #
    # Returns an array of symbols representing the directives.
    def supported_directives
      @supported_directives ||= if VARIATIONS[@parsed_ua.browser]
        if @parsed_ua.browser == "Firefox" && @parsed_ua.version >= VERSION_46
          VARIATIONS["FirefoxTransitional"]
        else
          VARIATIONS[@parsed_ua.browser]
        end
      else
        VARIATIONS[OTHER]
      end
    end

    def nonces_supported?
      @nonces_supported ||= MODERN_BROWSERS.include?(@parsed_ua.browser)
    end

    def symbol_to_hyphen_case(sym)
      sym.to_s.tr('_', '-')
    end
  end
end
