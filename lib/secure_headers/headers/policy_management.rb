module SecureHeaders
  module PolicyManagement
    def self.included(base)
      base.extend(ClassMethods)
    end

    MODERN_BROWSERS = %w(Chrome Opera Firefox)
    DEFAULT_VALUE = "default-src https:".freeze
    DEFAULT_CONFIG = { default_src: %w(https:) }.freeze
    HEADER_NAME = "Content-Security-Policy".freeze
    REPORT_ONLY = "Content-Security-Policy-Report-Only".freeze
    HEADER_NAMES = [HEADER_NAME, REPORT_ONLY]
    DATA_PROTOCOL = "data:".freeze
    BLOB_PROTOCOL = "blob:".freeze
    SELF = "'self'".freeze
    NONE = "'none'".freeze
    STAR = "*".freeze
    UNSAFE_INLINE = "'unsafe-inline'".freeze
    UNSAFE_EVAL = "'unsafe-eval'".freeze

    # leftover deprecated values that will be in common use upon upgrading.
    DEPRECATED_SOURCE_VALUES = [SELF, NONE, UNSAFE_EVAL, UNSAFE_INLINE, "inline", "eval"].map { |value| value.delete("'") }.freeze

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
    UPGRADE_INSECURE_REQUESTS = :upgrade_insecure_requests
    DIRECTIVES_DRAFT = [
      BLOCK_ALL_MIXED_CONTENT,
      UPGRADE_INSECURE_REQUESTS
    ].freeze

    EDGE_DIRECTIVES = DIRECTIVES_1_0
    SAFARI_DIRECTIVES = DIRECTIVES_1_0

    FIREFOX_UNSUPPORTED_DIRECTIVES = [
      BLOCK_ALL_MIXED_CONTENT,
      CHILD_SRC,
      PLUGIN_TYPES
    ].freeze

    FIREFOX_46_DEPRECATED_DIRECTIVES = [
      FRAME_SRC
    ].freeze

    FIREFOX_46_UNSUPPORTED_DIRECTIVES = [
      BLOCK_ALL_MIXED_CONTENT,
      PLUGIN_TYPES
    ].freeze

    FIREFOX_DIRECTIVES = (
      DIRECTIVES_2_0 + DIRECTIVES_DRAFT - FIREFOX_UNSUPPORTED_DIRECTIVES
    ).freeze

    FIREFOX_46_DIRECTIVES = (
      DIRECTIVES_2_0 + DIRECTIVES_DRAFT - FIREFOX_46_UNSUPPORTED_DIRECTIVES - FIREFOX_46_DEPRECATED_DIRECTIVES
    ).freeze

    CHROME_DIRECTIVES = (
      DIRECTIVES_2_0 + DIRECTIVES_DRAFT
    ).freeze

    ALL_DIRECTIVES = [DIRECTIVES_1_0 + DIRECTIVES_2_0 + DIRECTIVES_3_0 + DIRECTIVES_DRAFT].flatten.uniq.sort

    # Think of default-src and report-uri as the beginning and end respectively,
    # everything else is in between.
    BODY_DIRECTIVES = ALL_DIRECTIVES - [DEFAULT_SRC, REPORT_URI]

    # These are directives that do not inherit the default-src value. This is
    # useful when calling #combine_policies.
    NON_FETCH_SOURCES = [
      BASE_URI,
      FORM_ACTION,
      FRAME_ANCESTORS,
      PLUGIN_TYPES,
      REPORT_URI
    ]

    FETCH_SOURCES = ALL_DIRECTIVES - NON_FETCH_SOURCES

    VARIATIONS = {
      "Chrome" => CHROME_DIRECTIVES,
      "Opera" => CHROME_DIRECTIVES,
      "Firefox" => FIREFOX_DIRECTIVES,
      "FirefoxTransitional" => FIREFOX_46_DIRECTIVES,
      "Safari" => SAFARI_DIRECTIVES,
      "Edge" => EDGE_DIRECTIVES,
      "Other" => CHROME_DIRECTIVES
    }.freeze

    OTHER = "Other".freeze

    DIRECTIVE_VALUE_TYPES = {
      BASE_URI                  => :source_list,
      BLOCK_ALL_MIXED_CONTENT   => :boolean,
      CHILD_SRC                 => :source_list,
      CONNECT_SRC               => :source_list,
      DEFAULT_SRC               => :source_list,
      FONT_SRC                  => :source_list,
      FORM_ACTION               => :source_list,
      FRAME_ANCESTORS           => :source_list,
      FRAME_SRC                 => :source_list,
      IMG_SRC                   => :source_list,
      MANIFEST_SRC              => :source_list,
      MEDIA_SRC                 => :source_list,
      OBJECT_SRC                => :source_list,
      PLUGIN_TYPES              => :source_list,
      REFLECTED_XSS             => :string,
      REPORT_URI                => :source_list,
      SANDBOX                   => :string,
      SCRIPT_SRC                => :source_list,
      STYLE_SRC                 => :source_list,
      UPGRADE_INSECURE_REQUESTS => :boolean
    }.freeze

    CONFIG_KEY = :csp
    STAR_REGEXP = Regexp.new(Regexp.escape(STAR))
    HTTP_SCHEME_REGEX = %r{\Ahttps?://}

    WILDCARD_SOURCES = [
      UNSAFE_EVAL,
      UNSAFE_INLINE,
      STAR,
      DATA_PROTOCOL,
      BLOB_PROTOCOL
    ].freeze

    META_CONFIGS = [
      :report_only,
      :preserve_schemes
    ].freeze

    module ClassMethods
      # Public: generate a header name, value array that is user-agent-aware.
      #
      # Returns a default policy if no configuration is provided, or a
      # header name and value based on the config.
      def make_header(config, user_agent)
        header = new(config, user_agent)
        [header.name, header.value]
      end

      # Public: Validates each source expression.
      #
      # Does not validate the invididual values of the source expression (e.g.
      # script_src => h*t*t*p: will not raise an exception)
      def validate_config!(config)
        return if config.nil? || config == OPT_OUT
        raise ContentSecurityPolicyConfigError.new(":default_src is required") unless config[:default_src]
        config.each do |key, value|
          if META_CONFIGS.include?(key)
            raise ContentSecurityPolicyConfigError.new("#{key} must be a boolean value") unless boolean?(value) || value.nil?
          else
            validate_directive!(key, value)
          end
        end
      end

      # Public: determine if merging +additions+ will cause a change to the
      # actual value of the config.
      #
      # e.g. config = { script_src: %w(example.org google.com)} and
      # additions = { script_src: %w(google.com)} then idempotent_additions? would return
      # because google.com is already in the config.
      def idempotent_additions?(config, additions)
        return true if config == OPT_OUT && additions == OPT_OUT
        return false if config == OPT_OUT
        config == combine_policies(config, additions)
      end

      # Public: combine the values from two different configs.
      #
      # original - the main config
      # additions - values to be merged in
      #
      # raises an error if the original config is OPT_OUT
      #
      # 1. for non-source-list values (report_only, block_all_mixed_content, upgrade_insecure_requests),
      # additions will overwrite the original value.
      # 2. if a value in additions does not exist in the original config, the
      # default-src value is included to match original behavior.
      # 3. if a value in additions does exist in the original config, the two
      # values are joined.
      def combine_policies(original, additions)
        if original == OPT_OUT
          raise ContentSecurityPolicyConfigError.new("Attempted to override an opt-out CSP config.")
        end

        original = Configuration.send(:deep_copy, original)
        populate_fetch_source_with_default!(original, additions)
        merge_policy_additions(original, additions)
      end

      def ua_to_variation(user_agent)
        family = user_agent.browser
        if family && VARIATIONS.key?(family)
          family
        else
          OTHER
        end
      end

      private

      # merge the two hashes. combine (instead of overwrite) the array values
      # when each hash contains a value for a given key.
      def merge_policy_additions(original, additions)
        original.merge(additions) do |directive, lhs, rhs|
          if source_list?(directive)
            (lhs.to_a + rhs.to_a).compact.uniq
          else
            rhs
          end
        end.reject { |_, value| value.nil? || value == [] } # this mess prevents us from adding empty directives.
      end

      # For each directive in additions that does not exist in the original config,
      # copy the default-src value to the original config. This modifies the original hash.
      def populate_fetch_source_with_default!(original, additions)
        # in case we would be appending to an empty directive, fill it with the default-src value
        additions.keys.each do |directive|
          if !original[directive] && ((source_list?(directive) && FETCH_SOURCES.include?(directive)) || nonce_added?(original, additions))
            if nonce_added?(original, additions)
              inferred_directive = directive.to_s.gsub(/_nonce/, "_src").to_sym
              unless original[inferred_directive] || NON_FETCH_SOURCES.include?(inferred_directive)
                original[inferred_directive] = original[:default_src]
              end
            else
              original[directive] = original[:default_src]
            end
          end
        end
      end

      def nonce_added?(original, additions)
        [:script_nonce, :style_nonce].each do |nonce|
          if additions[nonce] && !original[nonce]
            return true
          end
        end
      end

      def source_list?(directive)
        DIRECTIVE_VALUE_TYPES[directive] == :source_list
      end

      # Private: Validates that the configuration has a valid type, or that it is a valid
      # source expression.
      def validate_directive!(directive, source_expression)
        case ContentSecurityPolicy::DIRECTIVE_VALUE_TYPES[directive]
        when :boolean
          unless boolean?(source_expression)
            raise ContentSecurityPolicyConfigError.new("#{directive} must be a boolean value")
          end
        when :string
          unless source_expression.is_a?(String)
            raise ContentSecurityPolicyConfigError.new("#{directive} Must be a string. Found #{config.class}: #{config} value")
          end
        else
          validate_source_expression!(directive, source_expression)
        end
      end

      # Private: validates that a source expression:
      # 1. has a valid name
      # 2. is an array of strings
      # 3. does not contain any depreated, now invalid values (inline, eval, self, none)
      #
      # Does not validate the invididual values of the source expression (e.g.
      # script_src => h*t*t*p: will not raise an exception)
      def validate_source_expression!(directive, source_expression)
        ensure_valid_directive!(directive)
        ensure_array_of_strings!(directive, source_expression)
        ensure_valid_sources!(directive, source_expression)
      end

      def ensure_valid_directive!(directive)
        unless ContentSecurityPolicy::ALL_DIRECTIVES.include?(directive)
          raise ContentSecurityPolicyConfigError.new("Unknown directive #{directive}")
        end
      end

      def ensure_array_of_strings!(directive, source_expression)
        unless source_expression.is_a?(Array) && source_expression.compact.all? { |v| v.is_a?(String) }
          raise ContentSecurityPolicyConfigError.new("#{directive} must be an array of strings")
        end
      end

      def ensure_valid_sources!(directive, source_expression)
        source_expression.each do |source_expression|
          if ContentSecurityPolicy::DEPRECATED_SOURCE_VALUES.include?(source_expression)
            raise ContentSecurityPolicyConfigError.new("#{directive} contains an invalid keyword source (#{source_expression}). This value must be single quoted.")
          end
        end
      end

      def boolean?(source_expression)
        source_expression.is_a?(TrueClass) || source_expression.is_a?(FalseClass)
      end
    end
  end
end
