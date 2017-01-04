module SecureHeaders
  class ClearSiteDataConfigError < StandardError; end
  class ClearSiteData
    HEADER_NAME = "Clear-Site-Data".freeze
    TYPES = "types".freeze

    # Valid `types`
    CACHE = "cache".freeze
    COOKIES = "cookies".freeze
    STORAGE = "storage".freeze
    EXECTION_CONTEXTS = "executionContexts".freeze
    ALL_TYPES = [CACHE, COOKIES, STORAGE, EXECTION_CONTEXTS]

    CONFIG_KEY = :clear_site_data

    class << self
      # Public: make an Clear-Site-Data header name, value pair
      #
      # Returns nil if not configured, returns header name and value if configured.
      def make_header(config=nil)
        case config
        when nil, OPT_OUT, []
          # noop
        when Array
          [HEADER_NAME, JSON.dump(TYPES => config)]
        when true
          [HEADER_NAME, JSON.dump(TYPES => ALL_TYPES)]
        end
      end

      def validate_config!(config)
        case config
        when nil, OPT_OUT, true
          # valid
        when Array
          unless config.all? { |t| t.is_a?(String) }
            raise ClearSiteDataConfigError.new("types must be Strings")
          end

          begin
            JSON.dump(config)
          rescue JSON::GeneratorError, Encoding::UndefinedConversionError
            raise ClearSiteDataConfigError.new("types must serializable by JSON")
          end
        else
          raise ClearSiteDataConfigError.new("config must be an Array of Strings or `true`")
        end
      end
    end
  end
end
