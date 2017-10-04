# frozen_string_literal: true
module SecureHeaders
  class Middleware
    HPKP_SAME_HOST_WARNING = "[WARNING] HPKP report host should not be the same as the request host. See https://github.com/twitter/secureheaders/issues/166"

    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      config = SecureHeaders.config_for(req)
      if config.hpkp_report_host == req.host
        Kernel.warn(HPKP_SAME_HOST_WARNING)
      end

      flag_cookies!(headers, override_secure(env, config.cookies)) unless config.cookies == OPT_OUT
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies!(headers, config)
      if cookies = headers["Set-Cookie"]
        # Support Rails 2.3 / Rack 1.1 arrays as headers
        cookies = cookies.split("\n") unless cookies.is_a?(Array)

        headers["Set-Cookie"] = cookies.map do |cookie|
          SecureHeaders::Cookie.new(cookie, config).to_s
        end.join("\n")
      end
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
