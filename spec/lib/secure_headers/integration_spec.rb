require "spec_helper"

describe SecureHeaders::Middleware do
  let(:app) { ->(env) { [200, env, "app"] } }

  let :middleware do
    SecureHeaders::Middleware.new(app)
  end

  it "sets the headers" do
    _, env = middleware.call env_for('https://looocalhost')
    expect_default_values(env)
  end

  it "respects overrides" do
    request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
    SecureHeaders::override_x_frame_options(request, "DENY")
    _, env = middleware.call request.env
    expect(env[SecureHeaders::XFrameOptions::HEADER_NAME]).to eq("DENY")
  end

  def env_for url, opts={}
    Rack::MockRequest.env_for(url, opts)
  end
end
