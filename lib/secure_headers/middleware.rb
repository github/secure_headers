module SecureHeaders
  class Middleware
    SECURE_COOKIE_REGEXP = /;\s*secure\s*(;|$)/i.freeze

    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      config = SecureHeaders.config_for(req)
      flag_cookies_as_secure!(headers) if config.secure_cookies
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies_as_secure!(headers)
      if cookies = headers['Set-Cookie']
        # Support Rails 2.3 / Rack 1.1 arrays as headers
        cookies = cookies.split("\n") unless cookies.is_a?(Array)

        headers['Set-Cookie'] = cookies.map do |cookie|
          if cookie !~ SECURE_COOKIE_REGEXP
            "#{cookie}; secure"
          else
            cookie
          end
        end.join("\n")
      end
    end
  end
end
