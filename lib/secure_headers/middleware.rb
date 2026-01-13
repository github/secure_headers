# frozen_string_literal: true
module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      # Rack::Headers is available in Rack 3.x and later
      # So we should pull the headers into that structure if possible
      if defined?(Rack::Headers)
        headers = Rack::Headers[headers]
      end

      config = SecureHeaders.config_for(req)
      flag_cookies!(headers, override_secure(env, config.cookies)) unless config.cookies == OPT_OUT
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies!(headers, config)
      cookies = headers["Set-Cookie"]
      return unless cookies

      cookies_array = cookies.is_a?(Array) ? cookies : cookies.split("\n")
      secured_cookies = cookies_array.map { |cookie| SecureHeaders::Cookie.new(cookie, config).to_s }
      headers["Set-Cookie"] = cookies.is_a?(Array) ? secured_cookies : secured_cookies.join("\n")
    end

    # disable Secure cookies for non-https requests
    def override_secure(env, config = {})
      if scheme(env) != "https" && config != OPT_OUT
        config[:secure] = OPT_OUT
      end

      config
    end

    # derived from https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L119
    def scheme(env)
      if env["HTTPS"] == "on" || env["HTTP_X_SSL_REQUEST"] == "on"
        "https"
      elsif env["HTTP_X_FORWARDED_PROTO"]
        env["HTTP_X_FORWARDED_PROTO"].split(",")[0]
      else
        env["rack.url_scheme"]
      end
    end
  end
end
