# frozen_string_literal: true
module SecureHeaders
  module PolicyManagement
    def self.included(base)
      base.extend(ClassMethods)
    end

    MODERN_BROWSERS = %w(Chrome Opera Firefox)
    DEFAULT_CONFIG = {
      default_src: %w(https:),
      img_src: %w(https: data: 'self'),
      object_src: %w('none'),
      script_src: %w(https:),
      style_src: %w('self' 'unsafe-inline' https:),
      form_action: %w('self')
    }.freeze
    DATA_PROTOCOL = "data:".freeze
    BLOB_PROTOCOL = "blob:".freeze
    SELF = "'self'".freeze
    NONE = "'none'".freeze
    STAR = "*".freeze
    UNSAFE_INLINE = "'unsafe-inline'".freeze
    UNSAFE_EVAL = "'unsafe-eval'".freeze
    STRICT_DYNAMIC = "'strict-dynamic'".freeze

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
    BLOCK_ALL_MIXED_CONTENT = :block_all_mixed_content
    MANIFEST_SRC = :manifest_src
    UPGRADE_INSECURE_REQUESTS = :upgrade_insecure_requests
    DIRECTIVES_3_0 = [
      DIRECTIVES_2_0,
      BLOCK_ALL_MIXED_CONTENT,
      MANIFEST_SRC,
      UPGRADE_INSECURE_REQUESTS
    ].flatten.freeze

    EDGE_DIRECTIVES = DIRECTIVES_1_0
    SAFARI_DIRECTIVES = DIRECTIVES_1_0
    SAFARI_10_DIRECTIVES = DIRECTIVES_2_0

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
      DIRECTIVES_3_0 - FIREFOX_UNSUPPORTED_DIRECTIVES
    ).freeze

    FIREFOX_46_DIRECTIVES = (
      DIRECTIVES_3_0 - FIREFOX_46_UNSUPPORTED_DIRECTIVES - FIREFOX_46_DEPRECATED_DIRECTIVES
    ).freeze

    CHROME_DIRECTIVES = (
      DIRECTIVES_3_0
    ).freeze

    ALL_DIRECTIVES = (DIRECTIVES_1_0 + DIRECTIVES_2_0 + DIRECTIVES_3_0).uniq.sort

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
      "SafariTransitional" => SAFARI_10_DIRECTIVES,
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
      REPORT_URI                => :source_list,
      SANDBOX                   => :source_list,
      SCRIPT_SRC                => :source_list,
      STYLE_SRC                 => :source_list,
      UPGRADE_INSECURE_REQUESTS => :boolean
    }.freeze


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

    NONCES = [
      :script_nonce,
      :style_nonce
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
        return if config.nil? || config.opt_out?
        raise ContentSecurityPolicyConfigError.new(":default_src is required") unless config.directive_value(:default_src)
        if config.directive_value(:script_src).nil?
          raise ContentSecurityPolicyConfigError.new(":script_src is required, falling back to default-src is too dangerous. Use `script_src: OPT_OUT` to override")
        end

        ContentSecurityPolicyConfig.attrs.each do |key|
          value = config.directive_value(key)
          next unless value
          if META_CONFIGS.include?(key)
            raise ContentSecurityPolicyConfigError.new("#{key} must be a boolean value") unless boolean?(value) || value.nil?
          else
            validate_directive!(key, value)
          end
        end
      end

      # Public: check if a user agent supports CSP nonces
      #
      # user_agent - a String or a UserAgent object
      def nonces_supported?(user_agent)
        user_agent = UserAgent.parse(user_agent) if user_agent.is_a?(String)
        MODERN_BROWSERS.include?(user_agent.browser) ||
          user_agent.browser == "Safari" && (user_agent.version || CSP::FALLBACK_VERSION) >= CSP::VERSION_10
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
        if original == {}
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
        additions.each_key do |directive|
          if !original[directive] && ((source_list?(directive) && FETCH_SOURCES.include?(directive)) || nonce_added?(original, additions))
            if nonce_added?(original, additions)
              inferred_directive = directive.to_s.gsub(/_nonce/, "_src").to_sym
              unless original[inferred_directive] || NON_FETCH_SOURCES.include?(inferred_directive)
                original[inferred_directive] = default_for(directive, original)
              end
            else
              original[directive] = default_for(directive, original)
            end
          end
        end
      end

      def default_for(directive, original)
        return original[FRAME_SRC] if directive == CHILD_SRC && original[FRAME_SRC]
        return original[CHILD_SRC] if directive == FRAME_SRC && original[CHILD_SRC]
        original[DEFAULT_SRC]
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
        if (!source_expression.is_a?(Array) || !source_expression.compact.all? { |v| v.is_a?(String) }) && source_expression != OPT_OUT
          raise ContentSecurityPolicyConfigError.new("#{directive} must be an array of strings")
        end
      end

      def ensure_valid_sources!(directive, source_expression)
        return if source_expression == OPT_OUT
        source_expression.each do |expression|
          if ContentSecurityPolicy::DEPRECATED_SOURCE_VALUES.include?(expression)
            raise ContentSecurityPolicyConfigError.new("#{directive} contains an invalid keyword source (#{expression}). This value must be single quoted.")
          end
        end
      end

      def boolean?(source_expression)
        source_expression.is_a?(TrueClass) || source_expression.is_a?(FalseClass)
      end
    end
  end
end
