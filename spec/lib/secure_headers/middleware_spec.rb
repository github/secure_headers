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
          Configuration.default { |config| config.secure_cookies = true }
          request = Rack::MockRequest.new(cookie_middleware)
          response = request.get '/'
          expect(response.headers['Set-Cookie']).to match(Middleware::SECURE_COOKIE_REGEXP)
        end
      end

      context "cookies should not be flagged" do
        it "does not flags cookies as secure" do
          Configuration.default { |config| config.secure_cookies = false }
          request = Rack::MockRequest.new(cookie_middleware)
          response = request.get '/'
          expect(response.headers['Set-Cookie']).not_to match(Middleware::SECURE_COOKIE_REGEXP)
        end
      end
    end

    context "cookies" do
      context "secure cookies" do
        context "when secure is a boolean" do
          it "flags cookies as secure" do
            Configuration.default { |config| config.cookies = { secure: true } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).to match(Middleware::SECURE_COOKIE_REGEXP)
          end
        end

        context "when secure is a Hash" do
          it "flags cookies as secure when whitelisted" do
            Configuration.default { |config| config.cookies = { secure: { only: ['foo']} } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).to match(Middleware::SECURE_COOKIE_REGEXP)
          end

          it "does not flag cookies as secure when excluded" do
            Configuration.default { |config| config.cookies = { secure: { except: ['foo']} } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).not_to match(Middleware::SECURE_COOKIE_REGEXP)
          end
        end
      end

      context "HttpOnly cookies" do
        context "when httponly is a boolean" do
          it "flags cookies as HttpOnly" do
            Configuration.default { |config| config.cookies = { httponly: true } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).to match(Middleware::HTTPONLY_COOKIE_REGEXP)
          end
        end

        context "when secure is a Hash" do
          it "flags cookies as secure when whitelisted" do
            Configuration.default { |config| config.cookies = { httponly: { only: ['foo']} } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).to match(Middleware::HTTPONLY_COOKIE_REGEXP)
          end

          it "does not flag cookies as secure when excluded" do
            Configuration.default { |config| config.cookies = { httponly: { except: ['foo']} } }
            request = Rack::MockRequest.new(cookie_middleware)
            response = request.get '/'
            expect(response.headers['Set-Cookie']).not_to match(Middleware::HTTPONLY_COOKIE_REGEXP)
          end
        end
      end
    end
  end
end
