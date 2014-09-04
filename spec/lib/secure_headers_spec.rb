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
    allow(request).to receive_message_chain(:env, :[]=)
  end

  ALL_HEADERS = Hash[[:hsts, :csp, :x_frame_options, :x_content_type_options, :x_xss_protection].map{|header| [header, false]}]

  def should_add_csp_to_env options
    expect(SecureHeaders::ContentSecurityPolicy).to receive(:add_to_env).
      with(subject.request, subject, options)
  end

  def should_not_add_csp_to_env
    expect(SecureHeaders::ContentSecurityPolicy).not_to receive(:add_to_env)
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
      config.x_download_options = nil
    end
  end

  def set_security_headers(subject)
    subject.set_csp_header
    subject.set_hsts_header
    subject.set_x_frame_options_header
    subject.set_x_content_type_options_header
    subject.set_x_xss_protection_header
    subject.set_x_download_options_header
  end

  describe "#ensure_security_headers" do
    it "sets a before filter" do
      options = {}
      expect(DummyClass).to receive(:before_filter).exactly(6).times
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
        # This is only 5 because `set_csp_header` does not actually set a header;
        # it adds metadata to ENV that is used to set a header later by a middleware.
        number_of_headers = 5
        expect(subject).to receive(:set_header).exactly(number_of_headers).times # a request for a given header
        subject.set_csp_header
        subject.set_x_frame_options_header
        subject.set_hsts_header
        subject.set_x_xss_protection_header
        subject.set_x_content_type_options_header
        subject.set_x_download_options_header
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

    it "does not set the X-Download-Options header if disabled" do
      should_not_assign_header(XDO_HEADER_NAME)
      subject.set_x_download_options_header(false)
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
          config.x_download_options = false
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

  describe "#set_x_download_options_header" do
    it "sets the X-Download-Options header" do
      should_assign_header(XDO_HEADER_NAME, SecureHeaders::XDownloadOptions::Constants::DEFAULT_VALUE)
      subject.set_x_download_options_header
    end

    it "allows a custom X-Download-Options header" do
      should_assign_header(XDO_HEADER_NAME, "noopen")
      subject.set_x_download_options_header(:value => 'noopen')
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

    it "allows you to specify preload" do
      should_assign_header(HSTS_HEADER_NAME, "max-age=#{HSTS_MAX_AGE}; includeSubdomains; preload")
      subject.set_hsts_header(:max_age => HSTS_MAX_AGE, :include_subdomains => true, :preload => true)
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
    context "when enabled" do
      it "adds CSP metadata to env" do
        options = {:ua => 'foo'}
        should_add_csp_to_env(options)
        subject.set_csp_header(options)
      end
    end

    context "when not enabled" do
      it "does not ad CSP metadata to env" do
        options = false
        should_not_add_csp_to_env
        subject.set_csp_header(options)
      end
    end
  end
end
