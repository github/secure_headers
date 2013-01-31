require 'spec_helper'

# half spec test, half integration test...
describe SecureHeaders do
  class DummyClass
    include ::SecureHeaders
  end

  subject {DummyClass.new}
  let(:headers) {double}
  let(:response) {double(:headers => headers)}
  let(:max_age) {99}
  let(:request) {double(:ssl? => true, :url => 'https://example.com')}

  before(:each) do
    stub_user_agent(nil)
    headers.stub(:[])
    subject.stub(:response).and_return(response)
    subject.stub(:request).and_return(request)
  end

  ALL_HEADERS = Hash[[:hsts, :csp, :x_frame_options, :x_content_type_options, :x_xss_protection].map{|header| [header, false]}]
  USER_AGENTS = {
    :firefox => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:14.0) Gecko/20100101 Firefox/14.0.1',
    :chrome => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5',
    :ie => 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
    :opera => 'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
    :ios5 => "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3"
  }

  describe "#set_header" do
    it "sets the given header and value" do
      headers.should_receive(:[]=).with("header", "value")
      subject.set_header("header", "value")
    end
  end

  def should_assign_header name, value
    subject.should_receive(:set_header).with(name, value)
  end

  def should_not_assign_header name
    subject.should_not_receive(:set_header).with(name, anything)
  end

  def stub_user_agent val
    request.stub_chain(:env, :[]).and_return(val)
  end

  def options_for header
    ALL_HEADERS.reject{|k,v| k == header}
  end

  def reset_config
    ::SecureHeaders::Configuration.configure do |config|
      config.hsts = nil
      config.x_frame_options = nil
      config.x_content_type_options = nil
      config.x_xss_protection = nil
      config.csp = nil
    end
  end

  describe "#ensure_security_headers" do
    it "sets a before filter" do
      options = {}
      DummyClass.should_receive(:before_filter).with(:set_security_headers)
      DummyClass.ensure_security_headers(options)
    end
  end

  describe "#set_security_headers" do
    before(:each) do
      SecureHeaders::ContentSecurityPolicy.stub(:new).and_return(double.as_null_object)
    end
    USER_AGENTS.each do |name, useragent|
      it "sets all default headers for #{name} (smoke test)" do
        stub_user_agent(useragent)
        number_of_headers = case name
        when :ie
          5
        when :opera
          4
        when :ios5
          3 # csp is disabled for ios5
        else
          4
        end

        subject.should_receive(:set_header).exactly(number_of_headers).times # a request for a given header
        subject.set_security_headers
      end
    end

    it "does not set the X-Content-Type-Options when disabled" do
      stub_user_agent(USER_AGENTS[:ie])
      should_not_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME)
      subject.set_security_headers(:x_content_type_options => false)
    end

    it "does not set the X-XSS-PROTECTION when disabled" do
      stub_user_agent(USER_AGENTS[:ie])
      should_not_assign_header(X_XSS_PROTECTION_HEADER_NAME)
      subject.set_security_headers(:x_xss_protection => false)
    end

    it "does not set the X-FRAME-OPTIONS header if disabled" do
      should_not_assign_header(XFO_HEADER_NAME)
      subject.set_security_headers(:x_frame_options => false)
    end

    it "does not set the hsts header if disabled" do
      should_not_assign_header(HSTS_HEADER_NAME)
      subject.set_security_headers(:hsts => false)
    end

    it "does not set the hsts header the request is over HTTP" do
      subject.stub_chain(:request, :ssl?).and_return(false)
      should_not_assign_header(HSTS_HEADER_NAME)
      subject.set_security_headers(:hsts => {:include_subdomains => true})
    end

    it "does not set the CSP header if disabled" do
      stub_user_agent(USER_AGENTS[:chrome])
      should_not_assign_header(WEBKIT_CSP_HEADER_NAME)
      subject.set_security_headers(options_for(:csp).merge(:csp => false))
    end

    # apparently iOS5 safari with CSP in enforce mode causes nothing to render
    # it has no effect in report-only mode (as in no report is sent)
    it "does not set CSP header if using ios5" do
      stub_user_agent(USER_AGENTS[:ios5])
      subject.should_not_receive(:set_csp_header)
      subject.set_security_headers(options_for(:csp))
    end

    context "when disabled by configuration settings" do
      it "does not set the X-Content-Type-Options when disabled" do
        ::SecureHeaders::Configuration.configure do |config|
          config.hsts = false
          config.x_frame_options = false
          config.x_content_type_options = false
          config.x_xss_protection = false
          config.csp = false
        end
        subject.should_not_receive(:set_header)
        subject.set_security_headers
        reset_config
      end
    end
  end

  describe "#set_x_frame_options_header" do
    it "sets the X-FRAME-OPTIONS header" do
      should_assign_header(XFO_HEADER_NAME, SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE)
      subject.set_x_frame_options_header
    end

    it "allows a custom X-FRAME-OPTIONS header" do
      should_assign_header(XFO_HEADER_NAME, "DENY")
      subject.set_x_frame_options_header(:value => 'DENY')
    end
  end

  context "when using IE" do
    before(:each) do
      stub_user_agent(USER_AGENTS[:ie])
    end

    describe "#set_x_xss_protection" do
      it "sets the XSS protection header" do
        should_assign_header(X_XSS_PROTECTION_HEADER_NAME, '1')
        subject.set_x_xss_protection_header
      end

      it "sets a custom X-XSS-PROTECTION header" do
        should_assign_header(X_XSS_PROTECTION_HEADER_NAME, '0')
        subject.set_x_xss_protection_header("0")
      end

      it "sets the block flag" do
        should_assign_header(X_XSS_PROTECTION_HEADER_NAME, '1; mode=block')
        subject.set_x_xss_protection_header(:mode => 'block', :value => 1)
      end
    end

    describe "#set_x_content_type_options" do
      it "sets the X-Content-Type-Options" do
        should_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME, 'nosniff')
        subject.set_x_content_type_options_header
      end

      it "lets you override X-Content-Type-Options" do
        should_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME, 'nosniff')
        subject.set_x_content_type_options_header(:value => 'nosniff')
      end
    end
  end

  describe "#set_csp_header" do
    context "when using Firefox" do
      it "sets CSP headers" do
        stub_user_agent(USER_AGENTS[:firefox])
        should_assign_header(FIREFOX_CSP_HEADER_NAME + "-Report-Only", FIREFOX_CSP_HEADER)
        subject.set_csp_header request
      end
    end

    context "when using Chrome" do
      it "sets default CSP header" do
        stub_user_agent(USER_AGENTS[:chrome])
        should_assign_header(WEBKIT_CSP_HEADER_NAME + "-Report-Only", WEBKIT_CSP_HEADER)
        subject.set_csp_header request
      end
    end

    context "when using a browser besides chrome/firefox" do
      it "sets the CSP header" do
        stub_user_agent(USER_AGENTS[:opera])
        should_assign_header(WEBKIT_CSP_HEADER_NAME + "-Report-Only", WEBKIT_CSP_HEADER)
        subject.set_csp_header request
      end
    end

    context "when using the experimental key" do
      before(:each) do
        stub_user_agent(USER_AGENTS[:chrome])
        @opts = {
          :enforce => true,
          :default_src => 'self',
          :script_src => 'https://mycdn.example.com',
          :experimental => {
            :script_src => 'self',
          }
        }
      end

      it "does not set the header in enforce mode if experimental is supplied, but enforce is disabled" do
        opts = @opts.merge(:enforce => false)
        should_assign_header(WEBKIT_CSP_HEADER_NAME + "-Report-Only", anything)
        should_not_assign_header(WEBKIT_CSP_HEADER_NAME)
        subject.set_csp_header request, opts
      end

      it "sets a header in enforce mode as well as report-only mode" do
        should_assign_header(WEBKIT_CSP_HEADER_NAME, anything)
        should_assign_header(WEBKIT_CSP_HEADER_NAME + "-Report-Only", anything)
        subject.set_csp_header request, @opts
      end
    end
  end
end
