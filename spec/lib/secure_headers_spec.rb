require 'spec_helper'

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
    allow(headers).to receive(:[])
    allow(subject).to receive(:response).and_return(response)
    allow(subject).to receive(:request).and_return(request)
  end

  ALL_HEADERS = Hash[[:hsts, :csp, :x_frame_options, :x_content_type_options, :x_xss_protection].map{|header| [header, false]}]
  USER_AGENTS = {
    :firefox => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:14.0) Gecko/20100101 Firefox/14.0.1',
    :chrome => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5',
    :ie => 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
    :opera => 'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
    :ios5 => "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    :ios6 => "Mozilla/5.0 (iPhone; CPU iPhone OS 614 like Mac OS X) AppleWebKit/536.26 (KHTML like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25",
    :safari5 => "Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3",
    :safari5_1 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10",
    :safari6 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/536.30.1 (KHTML like Gecko) Version/6.0.5 Safari/536.30.1"
  }

  def should_assign_header name, value
    expect(response.headers).to receive(:[]=).with(name, value)
  end

  def should_not_assign_header name
    expect(response.headers).not_to receive(:[]=).with(name, anything)
  end

  def stub_user_agent val
    allow(request).to receive_message_chain(:env, :[]).and_return(val)
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

  def set_security_headers(subject)
    subject.set_csp_header
    subject.set_hsts_header
    subject.set_x_frame_options_header
    subject.set_x_content_type_options_header
    subject.set_x_xss_protection_header
  end

  describe "#ensure_security_headers" do
    it "sets a before filter" do
      options = {}
      expect(DummyClass).to receive(:before_filter).exactly(5).times
      DummyClass.ensure_security_headers(options)
    end
  end

  describe "#set_header" do
    it "accepts name/value pairs" do
      should_assign_header("X-Hipster-Ipsum", "kombucha")
      subject.send(:set_header, "X-Hipster-Ipsum", "kombucha")
    end

    it "accepts header objects" do
      should_assign_header("Strict-Transport-Security", SecureHeaders::StrictTransportSecurity::Constants::DEFAULT_VALUE)
      subject.send(:set_header, SecureHeaders::StrictTransportSecurity.new)
    end
  end

  describe "#set_security_headers" do
    before(:each) do
      allow(SecureHeaders::ContentSecurityPolicy).to receive(:new).and_return(double.as_null_object)
    end
    USER_AGENTS.each do |name, useragent|
      it "sets all default headers for #{name} (smoke test)" do
        stub_user_agent(useragent)
        number_of_headers = 5
        expect(subject).to receive(:set_header).exactly(number_of_headers).times # a request for a given header
        subject.set_csp_header
        subject.set_x_frame_options_header
        subject.set_hsts_header
        subject.set_x_xss_protection_header
        subject.set_x_content_type_options_header
      end
    end

    it "does not set the X-Content-Type-Options header if disabled" do
      stub_user_agent(USER_AGENTS[:ie])
      should_not_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME)
      subject.set_x_content_type_options_header(false)
    end

    it "does not set the X-XSS-Protection header if disabled" do
      should_not_assign_header(X_XSS_PROTECTION_HEADER_NAME)
      subject.set_x_xss_protection_header(false)
    end

    it "does not set the X-Frame-Options header if disabled" do
      should_not_assign_header(XFO_HEADER_NAME)
      subject.set_x_frame_options_header(false)
    end

    it "does not set the HSTS header if disabled" do
      should_not_assign_header(HSTS_HEADER_NAME)
      subject.set_hsts_header(false)
    end

    it "does not set the HSTS header if request is over HTTP" do
      allow(subject).to receive_message_chain(:request, :ssl?).and_return(false)
      should_not_assign_header(HSTS_HEADER_NAME)
      subject.set_hsts_header({:include_subdomains => true})
    end

    it "does not set the CSP header if disabled" do
      stub_user_agent(USER_AGENTS[:chrome])
      should_not_assign_header(STANDARD_HEADER_NAME)
      subject.set_csp_header(options_for(:csp).merge(:csp => false))
    end

    context "when disabled by configuration settings" do
      it "does not set any headers when disabled" do
        ::SecureHeaders::Configuration.configure do |config|
          config.hsts = false
          config.x_frame_options = false
          config.x_content_type_options = false
          config.x_xss_protection = false
          config.csp = false
        end
        expect(subject).not_to receive(:set_header)
        set_security_headers(subject)
        reset_config
      end
    end
  end

  describe "#set_x_frame_options_header" do
    it "sets the X-Frame-Options header" do
      should_assign_header(XFO_HEADER_NAME, SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE)
      subject.set_x_frame_options_header
    end

    it "allows a custom X-Frame-Options header" do
      should_assign_header(XFO_HEADER_NAME, "DENY")
      subject.set_x_frame_options_header(:value => 'DENY')
    end
  end

  describe "#set_strict_transport_security" do
    it "sets the Strict-Transport-Security header" do
      should_assign_header(HSTS_HEADER_NAME, SecureHeaders::StrictTransportSecurity::Constants::DEFAULT_VALUE)
      subject.set_hsts_header
    end

    it "allows you to specific a custom max-age value" do
      should_assign_header(HSTS_HEADER_NAME, 'max-age=1234')
      subject.set_hsts_header(:max_age => 1234)
    end

    it "allows you to specify includeSubdomains" do
      should_assign_header(HSTS_HEADER_NAME, "max-age=#{HSTS_MAX_AGE}; includeSubdomains")
      subject.set_hsts_header(:max_age => HSTS_MAX_AGE, :include_subdomains => true)
    end
  end

  describe "#set_x_xss_protection" do
    it "sets the X-XSS-Protection header" do
      should_assign_header(X_XSS_PROTECTION_HEADER_NAME, SecureHeaders::XXssProtection::Constants::DEFAULT_VALUE)
      subject.set_x_xss_protection_header
    end

    it "sets a custom X-XSS-Protection header" do
      should_assign_header(X_XSS_PROTECTION_HEADER_NAME, '0')
      subject.set_x_xss_protection_header("0")
    end

    it "sets the block flag" do
      should_assign_header(X_XSS_PROTECTION_HEADER_NAME, '1; mode=block')
      subject.set_x_xss_protection_header(:mode => 'block', :value => 1)
    end
  end

  describe "#set_x_content_type_options" do
    USER_AGENTS.each do |useragent|
      context "when using #{useragent}" do
        before(:each) do
          stub_user_agent(USER_AGENTS[useragent])
        end

        it "sets the X-Content-Type-Options header" do
          should_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME, SecureHeaders::XContentTypeOptions::Constants::DEFAULT_VALUE)
          subject.set_x_content_type_options_header
        end

        it "lets you override X-Content-Type-Options" do
          should_assign_header(X_CONTENT_TYPE_OPTIONS_HEADER_NAME, 'nosniff')
          subject.set_x_content_type_options_header(:value => 'nosniff')
        end
      end
    end
  end

  describe "#set_csp_header" do
    context "when using Firefox" do
      it "sets CSP headers" do
        stub_user_agent(USER_AGENTS[:firefox])
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", DEFAULT_CSP_HEADER)
        subject.set_csp_header
      end
    end

    context "when using Chrome" do
      it "sets default CSP header" do
        stub_user_agent(USER_AGENTS[:chrome])
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", DEFAULT_CSP_HEADER)
        subject.set_csp_header
      end
    end

    context "when using a browser besides chrome/firefox" do
      it "sets the CSP header" do
        stub_user_agent(USER_AGENTS[:opera])
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", DEFAULT_CSP_HEADER)
        subject.set_csp_header
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
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", anything)
        should_not_assign_header(STANDARD_HEADER_NAME)
        subject.set_csp_header(opts)
      end

      it "sets a header in enforce mode as well as report-only mode" do
        should_assign_header(STANDARD_HEADER_NAME, anything)
        should_assign_header(STANDARD_HEADER_NAME + "-Report-Only", anything)
        subject.set_csp_header(@opts)
      end
    end
  end
end
