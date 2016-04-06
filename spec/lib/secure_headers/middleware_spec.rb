require "spec_helper"

module SecureHeaders
  describe Middleware do
    let(:app) { lambda { |env| [200, env, "app"] } }
    let(:cookie_app) { lambda { |env| [200, env.merge("Set-Cookie" => "foo=bar"), "app"] } }

    let(:middleware) { Middleware.new(app) }
    let(:cookie_middleware) { Middleware.new(cookie_app) }

    before(:each) do
      reset_config
      Configuration.default do |config|
        # use all default provided by the library
      end
    end

    it "sets the headers" do
      _, env = middleware.call(Rack::MockRequest.env_for("https://looocalhost", {}))
      expect_default_values(env)
    end

    it "respects overrides" do
      request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
      SecureHeaders.override_x_frame_options(request, "DENY")
      _, env = middleware.call request.env
      expect(env[XFrameOptions::HEADER_NAME]).to eq("DENY")
    end

    it "uses named overrides" do
      Configuration.override("my_custom_config") do |config|
        config.csp[:script_src] = %w(example.org)
      end
      request = Rack::Request.new({})
      SecureHeaders.use_secure_headers_override(request, "my_custom_config")
      expect(request.env[SECURE_HEADERS_CONFIG]).to be(Configuration.get("my_custom_config"))
      _, env = middleware.call request.env
      expect(env[CSP::HEADER_NAME]).to match("example.org")
    end

    context "secure_cookies" do
      context "cookies should be flagged" do
        it "flags cookies as secure" do
          capture_warning do
            Configuration.default { |config| config.secure_cookies = true }
          end
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env['Set-Cookie']).to match(SecureHeaders::Cookie::SECURE_REGEXP)
        end
      end

      context "cookies should not be flagged" do
        it "does not flags cookies as secure" do
          capture_warning do
            Configuration.default { |config| config.secure_cookies = false }
          end
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env['Set-Cookie']).not_to match(SecureHeaders::Cookie::SECURE_REGEXP)
        end
      end
    end

    context "cookies" do
      it "flags cookies from configuration" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: true, samesite: true } }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env['Set-Cookie']).to match(SecureHeaders::Cookie::SECURE_REGEXP)
        expect(env['Set-Cookie']).to match(SecureHeaders::Cookie::HTTPONLY_REGEXP)
        expect(env['Set-Cookie']).to match(SecureHeaders::Cookie::SAMESITE_REGEXP)
      end

      it "disables secure cookies for non-https requests" do
        Configuration.default { |config| config.cookies = { secure: true } }

        request = Rack::Request.new("HTTPS" => "off")
        _, env = cookie_middleware.call request.env
        expect(env['Set-Cookie']).not_to match(SecureHeaders::Cookie::SECURE_REGEXP)
      end
    end
  end
end
