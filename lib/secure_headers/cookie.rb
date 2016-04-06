require 'cgi'

module SecureHeaders
  class CookiesConfigError < StandardError; end
  class Cookie
    SECURE_REGEXP = /;\s*secure\s*(;|$)/i.freeze
    HTTPONLY_REGEXP =/;\s*HttpOnly\s*(;|$)/i.freeze
    SAMESITE_REGEXP =/;\s*SameSite\s*(;|$)/i.freeze
    SAMESITE_LAX_REGEXP =/;\s*SameSite=Lax\s*(;|$)/i.freeze
    SAMESITE_STRICT_REGEXP =/;\s*SameSite=Strict\s*(;|$)/i.freeze

    REGEXES = {
      secure: SECURE_REGEXP,
      httponly: HTTPONLY_REGEXP,
      samesite: SAMESITE_REGEXP,
    }

    class << self
      def validate_config!(config)
        return if config.nil? || config == OPT_OUT
        raise CookiesConfigError.new("config must be a hash.") unless config.is_a? Hash

        # validate only boolean or Hash configuration
        [:secure, :httponly, :samesite].each do |attribute|
          if config[attribute] && !(config[attribute].is_a?(Hash) || config[attribute].is_a?(TrueClass) || config[attribute].is_a?(FalseClass))
            raise CookiesConfigError.new("#{attribute} cookie config must be a hash or boolean")
          end
        end

        [:secure, :httponly].each do |attribute|
          if config[attribute].is_a?(Hash) && config[attribute].key?(:only) && config[attribute].key?(:except)
            raise CookiesConfigError.new("#{attribute} cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
          end
        end

        if config[:samesite] && config[:samesite].is_a?(Hash)
          [:lax, :strict].each do |samesite_attribute|
            if config[:samesite][samesite_attribute].is_a?(Hash) && config[:samesite][samesite_attribute].key?(:only) && config[:samesite][samesite_attribute].key?(:except)
              raise CookiesConfigError.new("samesite #{samesite_attribute} cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
            end
          end
        end
      end
    end

    attr_reader :raw_cookie, :config

    def initialize(cookie, config)
      @raw_cookie = cookie
      @config = config
    end

    def to_s
      @raw_cookie.dup.tap do |c|
        c << "; secure" if secure?
        c << "; HttpOnly" if httponly?
        c << "; #{samesite_cookie}" if samesite?
      end
    end

    def secure?
      flag_cookie?(:secure) && !already_flagged?(:secure)
    end

    def httponly?
      flag_cookie?(:httponly) && !already_flagged?(:httponly)
    end

    def samesite?
      flag_samesite? && !already_flagged?(:samesite)
    end

    private

    def parsed_cookie
      @parsed_cookie ||= CGI::Cookie.parse(raw_cookie)
    end

    def already_flagged?(attribute)
      raw_cookie =~ REGEXES[attribute]
    end

    def flag_cookie?(attribute)
      case config[attribute]
      when TrueClass
        true
      when Hash
        conditionally_flag?(config[attribute])
      else
        false
      end
    end

    def conditionally_flag?(configuration)
      if(Array(configuration[:only]).any? && (Array(configuration[:only]) & parsed_cookie.keys).any?)
        true
      elsif(Array(configuration[:except]).any? && (Array(configuration[:except]) & parsed_cookie.keys).none?)
        true
      else
        false
      end
    end

    def samesite_cookie
      case config[:samesite]
      when TrueClass
        "SameSite"
      when Hash
        if flag_samesite_lax?
          "SameSite=Lax"
        elsif flag_samesite_strict?
          "SameSite=Strict"
        end
      end
    end

    def flag_samesite?
      case config[:samesite]
      when TrueClass
        true
      when Hash
        flag_samesite_lax? || flag_samesite_strict?
      else
        false
      end
    end

    def flag_samesite_lax?
      config[:samesite].key?(:lax) && conditionally_flag?(config[:samesite][:lax])
    end

    def flag_samesite_strict?
      config[:samesite].key?(:strict) && conditionally_flag?(config[:samesite][:strict])
    end
  end
end
