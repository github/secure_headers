require 'cgi'

module SecureHeaders
  class Middleware
    SECURE_COOKIE_REGEXP = /;\s*secure\s*(;|$)/i.freeze
    HTTPONLY_COOKIE_REGEXP =/;\s*HttpOnly\s*(;|$)/i.freeze
    SAMESITE_COOKIE_REGEXP =/;\s*SameSite\s*(;|$)/i.freeze

    ATTRIBUTES = {
      secure: "secure",
      httponly: "HttpOnly",
      samesite: "SameSite"
    }

    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      config = SecureHeaders.config_for(req)
      flag_cookies!(headers, config.cookies) if config.cookies
      flag_cookies!(headers, secure: true) if config.secure_cookies
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies!(headers, config)
      if cookies = headers['Set-Cookie']
        # Support Rails 2.3 / Rack 1.1 arrays as headers
        cookies = cookies.split("\n") unless cookies.is_a?(Array)

        headers['Set-Cookie'] = cookies.map do |cookie|
          cookie = flag_cookie!(:secure, cookie, config, SECURE_COOKIE_REGEXP)
          cookie = flag_cookie!(:httponly, cookie, config, HTTPONLY_COOKIE_REGEXP)
          cookie = flag_samesite_cookie!(:samesite, cookie, config)
        end.join("\n")
      end
    end

    def flag_cookie!(attribute, cookie, config = false, regexp)
      case config[attribute]
      when NilClass, FalseClass
        cookie
      when TrueClass
        flag_unless_matches(cookie, ATTRIBUTES[attribute], regexp)
      when Hash
        parsed_cookie = CGI::Cookie.parse(cookie)

        if((Array(config[attribute][:only]) & parsed_cookie.keys).any?)
          flag_unless_matches(cookie, ATTRIBUTES[attribute], regexp)
        elsif((Array(config[attribute][:except]) & parsed_cookie.keys).none?)
          flag_unless_matches(cookie, ATTRIBUTES[attribute], regexp)
        else
          cookie
        end
      end
    end

    def flag_samesite_cookie!(attribute, cookie, config = false)
      case config[attribute]
      when NilClass, FalseClass
        cookie
      when TrueClass
        flag_unless_matches(cookie, ATTRIBUTES[attribute], SAMESITE_COOKIE_REGEXP)
      when Hash
        parsed_cookie = CGI::Cookie.parse(cookie)

        if((Array(config[attribute][:only]) & parsed_cookie.keys).any?)
          flag_unless_matches(cookie, ATTRIBUTES[attribute], regexp)
        elsif((Array(config[attribute][:except]) & parsed_cookie.keys).none?)
          flag_unless_matches(cookie, ATTRIBUTES[attribute], regexp)
        else
          cookie
        end
      end
    end

    def flag_unless_matches(cookie, attribute, regexp)
      if cookie =~ regexp
        cookie
      else
        "#{cookie}; #{attribute}"
      end
    end
  end
end
