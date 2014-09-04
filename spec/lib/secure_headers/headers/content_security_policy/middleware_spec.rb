require 'spec_helper'

module SecureHeaders
  describe ContentSecurityPolicy::Middleware do

    let(:app) { double(:call => [200, headers, '']) }
    let(:env) { double }
    let(:headers) { double }
    let(:controller) { double }

    let(:default_config) do
      {
        :disable_chrome_extension => true,
        :disable_fill_missing => true,
        :default_src => 'https://*',
        :report_uri => '/csp_report',
        :script_src => 'inline eval https://* data:',
        :style_src => "inline https://* about:"
      }
    end

    def call_middleware(config = {}, options = {})
      config = default_config.merge(config)
      options = {
        :ua => USER_AGENTS[:chrome],
        :controller => controller,
      }.merge(options)
      expect(env).to receive(:[]).with(ENV_KEY).and_return(
        :config => config,
        :options => options,
      )
      ContentSecurityPolicy::Middleware.new(app).call(env)
    end

    context "when using Firefox" do
      it "sets CSP headers" do
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", /default-src/)
        call_middleware({}, :ua => USER_AGENTS[:firefox])
      end
    end

    context "when using Chrome" do
      it "sets default CSP header" do
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", /default-src/)
        call_middleware({}, :ua => USER_AGENTS[:chrome])
      end
    end

    context "when using a browser besides chrome/firefox" do
      it "sets the CSP header" do
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", /default-src/)
        call_middleware({}, :ua => USER_AGENTS[:opera])
      end
    end

    context "when using the experimental key" do
      let(:config) do
        default_config.merge(
          :enforce => true,
          :experimental => {
            :script_src => 'self',
          },
        )
      end

      it "does not set the header in enforce mode if experimental is supplied, but enforce is disabled" do
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", anything)
        should_not_assign_header(STANDARD_HEADER_NAME)
        call_middleware(config.merge(:enforce => false))
      end

      it "sets a header in enforce mode as well as report-only mode" do
        should_assign_header(STANDARD_HEADER_NAME, anything)
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", anything)
        call_middleware(config)
      end
    end
  end
end
