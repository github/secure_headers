require 'cgi'

module SecureHeaders
  class Cookie
    SECURE_REGEXP = /;\s*secure\s*(;|$)/i.freeze
    HTTPONLY_REGEXP =/;\s*HttpOnly\s*(;|$)/i.freeze
    SAMESITE_REGEXP =/;\s*SameSite\s*(;|$)/i.freeze

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
        c << "; SameSite" if samesite?
      end
    end

    def secure?
      already_flagged?(:secure) || flag_cookie?(:secure)
    end

    def httponly?
      already_flagged?(:httponly) || flag_cookie?(:httponly)
    end

    def samesite?
      already_flagged?(:samesite) || flag_samesite?
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
        if((Array(config[attribute][:only]) & parsed_cookie.keys).any?)
          true
        elsif((Array(config[attribute][:except]) & parsed_cookie.keys).none?)
          true
        else
          false
        end
      else
        false
      end
    end

    def flag_samesite?
      case config[:samesite]
      when TrueClass
        true
      else
        false
      end
    end
  end
end
