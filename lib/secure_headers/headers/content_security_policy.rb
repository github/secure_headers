# frozen_string_literal: true
require_relative "policy_management"
require_relative "content_security_policy_config"
require_relative "content_security_policy/parse_source_expression"

module SecureHeaders
  class ContentSecurityPolicy
    include PolicyManagement

    def initialize(config = nil)
      @config =
        if config.is_a?(Hash)
          if config[:report_only]
            ContentSecurityPolicyReportOnlyConfig.new(config || DEFAULT_CONFIG)
          else
            ContentSecurityPolicyConfig.new(config || DEFAULT_CONFIG)
          end
        elsif config.nil?
          ContentSecurityPolicyConfig.new(DEFAULT_CONFIG)
        else
          config
        end

      @preserve_schemes = @config.preserve_schemes
      @script_nonce = @config.script_nonce
      @style_nonce = @config.style_nonce
    end

    ##
    # Returns the name to use for the header. Either "Content-Security-Policy" or
    # "Content-Security-Policy-Report-Only"
    def name
      @config.class.const_get(:HEADER_NAME)
    end

    ##
    # Return the value of the CSP header
    def value
      @value ||=
        if @config
          build_value
        else
          DEFAULT_VALUE
        end
    end

    private

    # Private: converts the config object into a string representing a policy.
    # Places default-src at the first directive and report-uri as the last. All
    # others are presented in alphabetical order.
    #
    # Returns a content security policy header value.
    def build_value
      directives.map do |directive_name|
        case DIRECTIVE_VALUE_TYPES[directive_name]
        when :source_list,
             :require_sri_for_list, # require_sri is a simple set of strings that don't need to deal with symbol casing
             :require_trusted_types_for_list
          build_source_list_directive(directive_name)
        when :boolean
          symbol_to_hyphen_case(directive_name) if @config.directive_value(directive_name)
        when :sandbox_list
          build_sandbox_list_directive(directive_name)
        when :media_type_list
          build_media_type_list_directive(directive_name)
        end
      end.compact.join("; ")
    end

    def build_sandbox_list_directive(directive)
      return unless sandbox_list = @config.directive_value(directive)
      max_strict_policy = case sandbox_list
      when Array
        sandbox_list.empty?
      when true
        true
      else
        false
      end

      # A maximally strict sandbox policy is just the `sandbox` directive,
      # whith no configuraiton values.
      if max_strict_policy
        symbol_to_hyphen_case(directive)
      elsif sandbox_list && sandbox_list.any?
        [
          symbol_to_hyphen_case(directive),
          sandbox_list.uniq
        ].join(" ")
      end
    end

    def build_media_type_list_directive(directive)
      return unless media_type_list = @config.directive_value(directive)
      if media_type_list && media_type_list.any?
        [
          symbol_to_hyphen_case(directive),
          media_type_list.uniq
        ].join(" ")
      end
    end

    # Private: builds a string that represents one directive in a minified form.
    #
    # directive_name - a symbol representing the various ALL_DIRECTIVES
    #
    # Returns a string representing a directive.
    def build_source_list_directive(directive)
      source_list = @config.directive_value(directive)
      if source_list != OPT_OUT && source_list && source_list.any?
        cleaned_source_list = []
        semicolon_warned_yet = false
        source_list.map do |entry|
          if entry =~ /(\n|;)/
            if !semicolon_warned_yet
              Kernel.warn("#{directive} contains a #{$1} in #{source_list.join(" ").inspect} which will raise an error in future versions. It has been replaced with a blank space.")
              semicolon_warned_yet = true
            end
            split_entry = entry.split(/\n|;/).select{ | value | value != "" }
            cleaned_source_list.concat(split_entry)
          else
            cleaned_source_list.append(entry)
          end
        end

        puts cleaned_source_list

        minified_source_list = minify_source_list(directive, cleaned_source_list).join(" ")
        [symbol_to_hyphen_case(directive), minified_source_list].join(" ").strip
      end
    end

    # If a directive contains *, all other values are omitted.
    # If a directive contains 'none' but has other values, 'none' is ommitted.
    # Schemes are stripped (see http://www.w3.org/TR/CSP2/#match-source-expression)
    def minify_source_list(directive, source_list)
      source_list = source_list.compact
      if source_list.include?(STAR)
        keep_wildcard_sources(source_list)
      else
        source_list = populate_nonces(directive, source_list)
        source_list = reject_all_values_if_none(source_list)

        unless directive == REPORT_URI || @preserve_schemes
          source_list = strip_source_schemes(source_list)
        end
        dedup_source_list(source_list)
      end
    end

    # Discard trailing entries (excluding unsafe-*) since * accomplishes the same.
    def keep_wildcard_sources(source_list)
      source_list.select { |value| WILDCARD_SOURCES.include?(value) }
    end

    # Discard any 'none' values if more directives are supplied since none may override values.
    def reject_all_values_if_none(source_list)
      if source_list.length > 1
        source_list.reject { |value| value == NONE }
      else
        source_list
      end
    end

    # Removes duplicates and sources that already match an existing wild card.
    #
    # e.g. *.github.com asdf.github.com becomes *.github.com
    def dedup_source_list(sources)
      sources = sources.uniq
      host_source_expressions = sources.map { |source| parse_source_expression(source) }
      # TODO: Split by source expression type.
      wildcard_host_source_expressions = host_source_expressions.select { |source| source.has_wildcard? }
      
      filtered = host_source_expressions.select do |source|
        wildcard_host_source_expressions.none? { |wildcard_source| wildcard_source != source && wildcard_source.matches_same_or_superset?(source) }
      end

      # if wildcard_host_source_expressions.any?
      puts "--filtered---\n\n"
      puts filtered
      puts "---filtered2--\n\n"
      filtered.map { |source| source.to_s }
      puts "---filtered3--\n\n"
      filtered.map { |source| source.to_s }
    end

    # Private: append a nonce to the script/style directories if script_nonce
    # or style_nonce are provided.
    def populate_nonces(directive, source_list)
      case directive
      when SCRIPT_SRC
        append_nonce(source_list, @script_nonce)
      when STYLE_SRC
        append_nonce(source_list, @style_nonce)
      else
        source_list
      end
    end

    # Private: adds a nonce or 'unsafe-inline' depending on browser support.
    # If a nonce is populated, inline content is assumed.
    #
    # While CSP is backward compatible in that a policy with a nonce will ignore
    # unsafe-inline, this is more concise.
    def append_nonce(source_list, nonce)
      if nonce
        source_list.push("'nonce-#{nonce}'")
        source_list.push(UNSAFE_INLINE) unless @config[:disable_nonce_backwards_compatibility]
      end

      source_list
    end

    # Private: return the list of directives,
    # starting with default-src and ending with report-uri.
    def directives
      [
        DEFAULT_SRC,
        BODY_DIRECTIVES,
        REPORT_URI,
      ].flatten
    end

    # Private: Remove scheme from source expressions.
    def strip_source_schemes(source_list)
      source_list.map { |source_expression| source_expression.sub(HTTP_SCHEME_REGEX, "") }
    end

    def symbol_to_hyphen_case(sym)
      sym.to_s.tr("_", "-")
    end

    def source_scheme(source)
      source.match(/^([A-Za-z0-9\-\+.]+):\/\//)&.values_at(1)
    end
  end
end
