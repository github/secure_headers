require 'cgi'

module SecureHeaders
  class CookiesConfigError < StandardError; end
  class Cookie
    SECURE_REGEXP = /;\s*secure\s*(;|$)/i.freeze
    HTTPONLY_REGEXP =/;\s*HttpOnly\s*(;|$)/i.freeze
    SAMESITE_REGEXP =/;\s*SameSite\s*(;|$)/i.freeze
    SAMESITE_LAX_REGEXP =/;\s*SameSite=Lax\s*(;|$)/i.freeze
    SAMESITE_STRICT_REGEXP =/;\s*SameSite=Strict\s*(;|$)/i.freeze

    class << self
      def validate_config!(config)
        return if config.nil? || config == OPT_OUT
        raise CookiesConfigError.new("config must be a hash.") unless config.is_a? Hash

        # secure and httponly - validate only boolean or Hash configuration
        [:secure, :httponly].each do |attribute|
          if config[attribute] && !(config[attribute].is_a?(Hash) || config[attribute].is_a?(TrueClass) || config[attribute].is_a?(FalseClass))
            raise CookiesConfigError.new("#{attribute} cookie config must be a hash or boolean")
          end
        end

        # secure and httponly - validate exclusive use of only or except but not both at the same time
        [:secure, :httponly].each do |attribute|
          if config[attribute].is_a?(Hash)
            if config[attribute].key?(:only) && config[attribute].key?(:except)
              raise CookiesConfigError.new("#{attribute} cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
            end

            if (intersection = (config[attribute].fetch(:only, []) & config[attribute].fetch(:only, []))).any?
              raise CookiesConfigError.new("#{attribute} cookie config is invalid, cookies #{intersection.join(', ')} cannot be enforced as lax and strict")
            end
          end
        end

        if config[:samesite]
          raise CookiesConfigError.new("samesite cookie config must be a hash") unless config[:samesite].is_a?(Hash)

          # when configuring with booleans, only one enforcement is permitted
          if config[:samesite].key?(:lax) && config[:samesite][:lax].is_a?(TrueClass) && config[:samesite].key?(:strict)
            raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
          elsif config[:samesite].key?(:strict) && config[:samesite][:strict].is_a?(TrueClass) && config[:samesite].key?(:lax)
            raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
          end

          # validate Hash-based samesite configuration
          if config[:samesite].key?(:lax) && config[:samesite][:lax].is_a?(Hash)
            # validate exclusive use of only or except but not both at the same time
            if config[:samesite][:lax].key?(:only) && config[:samesite][:lax].key?(:except)
              raise CookiesConfigError.new("samesite lax cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
            end

            if config[:samesite].key?(:strict)
              # validate exclusivity of only and except members
              if (intersection = (config[:samesite][:lax].fetch(:only, []) & config[:samesite][:strict].fetch(:only, []))).any?
                raise CookiesConfigError.new("samesite cookie config is invalid, cookie(s) #{intersection.join(', ')} cannot be enforced as lax and strict")
              end

              if (intersection = (config[:samesite][:lax].fetch(:except, []) & config[:samesite][:strict].fetch(:except, []))).any?
                raise CookiesConfigError.new("samesite cookie config is invalid, cookie(s) #{intersection.join(', ')} cannot be enforced as lax and strict")
              end
            end
          end

          if config[:samesite].key?(:strict) && config[:samesite][:strict].is_a?(Hash)
            # validate exclusive use of only or except but not both at the same time
            if config[:samesite][:strict].key?(:only) && config[:samesite][:strict].key?(:except)
              raise CookiesConfigError.new("samesite strict cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
            end
          end
        end
      end
    end

    attr_reader :raw_cookie, :config

    def initialize(cookie, config)
      @raw_cookie = cookie
      @config = config
      @attributes = {
        httponly: nil,
        samesite: nil,
        secure: nil,
      }

      parse(cookie)
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
      @attributes[attribute]
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
      if flag_samesite_lax?
        "SameSite=Lax"
      elsif flag_samesite_strict?
        "SameSite=Strict"
      end
    end

    def flag_samesite?
      flag_samesite_lax? || flag_samesite_strict?
    end

    def flag_samesite_lax?
      flag_samesite_enforcement?(:lax)
    end

    def flag_samesite_strict?
      flag_samesite_enforcement?(:strict)
    end

    def flag_samesite_enforcement?(mode)
      return unless config[:samesite]

      case config[:samesite][mode]
      when Hash
        conditionally_flag?(config[:samesite][mode])
      when TrueClass
        true
      else
        false
      end
    end

    def parse(cookie)
      return unless cookie

      cookie.split(/[;,]\s?/).each do |pairs|
        name, values = pairs.split('=',2)
        name = CGI.unescape(name)

        attribute = name.downcase.to_sym
        if @attributes.has_key?(attribute)
          @attributes[attribute] = values || true
        end
      end
    end
  end
end
