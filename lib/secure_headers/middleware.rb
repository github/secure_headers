module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      config = SecureHeaders.config_for(req)
      flag_cookies!(headers, config.cookies) if config.cookies
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
          SecureHeaders::Cookie.new(cookie, config).to_s
        end.join("\n")
      end
    end
  end
end
