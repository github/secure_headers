require "spec_helper"

module SecureHeaders
  describe Middleware do
    let(:app) { ->(env) { [200, env, "app"] } }

    let :middleware do
      Middleware.new(app)
    end

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
      _, env = middleware.call request.env
      expect(env[CSP::HEADER_NAME]).to match("example.org")
    end
  end
end
