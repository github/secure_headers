# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Middleware do
    let(:app) { lambda { |env| [200, env, "app"] } }
    let(:cookie_app) { lambda { |env| [200, env.merge("Set-Cookie" => "foo=bar"), "app"] } }

    let(:middleware) { Middleware.new(app) }
    let(:cookie_middleware) { Middleware.new(cookie_app) }

    before(:each) do
      reset_config
      Configuration.default
    end

    it "warns if the hpkp report-uri host is the same as the current host" do
      report_host = "report-uri.io"
      reset_config
      Configuration.default do |config|
        config.hpkp = {
          max_age: 10000000,
          pins: [
            {sha256: "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"},
            {sha256: "73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f"}
          ],
          report_uri: "https://#{report_host}/example-hpkp"
        }
      end

      expect(Kernel).to receive(:warn).with(Middleware::HPKP_SAME_HOST_WARNING)

      middleware.call(Rack::MockRequest.env_for("https://#{report_host}", {}))
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
      _, env = middleware.call request.env
      expect(env[ContentSecurityPolicyConfig::HEADER_NAME]).to match("example.org")
    end

    context "cookies" do
      before(:each) do
        reset_config
      end
      context "cookies should be flagged" do
        it "flags cookies as secure" do
          Configuration.default { |config| config.cookies = {secure: true, httponly: OPT_OUT, samesite: OPT_OUT} }
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env["Set-Cookie"]).to eq("foo=bar; secure")
        end
      end

      it "allows opting out of cookie protection with OPT_OUT alone" do
        Configuration.default { |config| config.cookies = OPT_OUT }

        # do NOT make this request https. non-https requests modify a config,
        # causing an exception when operating on OPT_OUT. This ensures we don't
        # try to modify the config.
        request = Rack::Request.new({})
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")
      end

      context "cookies should not be flagged" do
        it "does not flags cookies as secure" do
          Configuration.default { |config| config.cookies = {secure: OPT_OUT, httponly: OPT_OUT, samesite: OPT_OUT}  }
          request = Rack::Request.new("HTTPS" => "on")
          _, env = cookie_middleware.call request.env
          expect(env["Set-Cookie"]).to eq("foo=bar")
        end
      end
    end

    context "cookies" do
      before(:each) do
        reset_config
      end
      it "flags cookies from configuration" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: true, samesite: { lax: true} } }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env["Set-Cookie"]).to eq("foo=bar; secure; HttpOnly; SameSite=Lax")
      end

      it "flags cookies with a combination of SameSite configurations" do
        cookie_middleware = Middleware.new(lambda { |env| [200, env.merge("Set-Cookie" => ["_session=foobar", "_guest=true"]), "app"] })

        Configuration.default { |config| config.cookies = { samesite: { lax: { except: ["_session"] }, strict: { only: ["_session"] } }, httponly: OPT_OUT, secure: OPT_OUT} }
        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env

        expect(env["Set-Cookie"]).to match("_session=foobar; SameSite=Strict")
        expect(env["Set-Cookie"]).to match("_guest=true; SameSite=Lax")
      end

      it "disables secure cookies for non-https requests" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: OPT_OUT, samesite: OPT_OUT } }

        request = Rack::Request.new("HTTPS" => "off")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")
      end

      it "sets the secure cookie flag correctly on interleaved http/https requests" do
        Configuration.default { |config| config.cookies = { secure: true, httponly: OPT_OUT, samesite: OPT_OUT } }

        request = Rack::Request.new("HTTPS" => "off")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar")

        request = Rack::Request.new("HTTPS" => "on")
        _, env = cookie_middleware.call request.env
        expect(env["Set-Cookie"]).to eq("foo=bar; secure")
      end
    end
  end
end
