require 'cgi'

module SecureHeaders
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
      if((Array(configuration[:only]) & parsed_cookie.keys).any?)
        true
      elsif((Array(configuration[:except]) & parsed_cookie.keys).none?)
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
        if config[:samesite].key?(:lax)
          "SameSite=Lax"
        elsif config[:samesite].key?(:strict)
          "SameSite=Strict"
        end
      else
        false
      end
    end

    def flag_samesite?
      case config[:samesite]
      when TrueClass
        true
      when Hash
        if config[:samesite].key?(:lax)
          conditionally_flag?(config[:samesite][:lax])
        elsif config[:samesite].key?(:strict)
          conditionally_flag?(config[:samesite][:strict])
        else
          false
        end
      else
        false
      end
    end
  end
end
