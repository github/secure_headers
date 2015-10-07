require 'spec_helper'

describe SecureHeaders do
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

  def stub_user_agent val
    allow(request).to receive_message_chain(:env, :[]).and_return(val)
  end

  def reset_config
    ::SecureHeaders::Configuration.configure do |config|
      config.hpkp = nil
      config.hsts = nil
      config.x_frame_options = nil
      config.x_content_type_options = nil
      config.x_xss_protection = nil
      config.csp = nil
      config.x_download_options = nil
      config.x_permitted_cross_domain_policies = nil
    end
  end

  xit "does not set the HSTS header if request is over HTTP" do
    allow(subject).to receive_message_chain(:request, :ssl?).and_return(false)
    should_not_assign_header(HSTS_HEADER_NAME)
    subject.set_hsts_header({:include_subdomains => true})
  end

  xit "does not set the HPKP header if request is over HTTP" do
    allow(subject).to receive_message_chain(:request, :ssl?).and_return(false)
    should_not_assign_header(HPKP_HEADER_NAME)
    subject.set_hpkp_header(:max_age => 1234)
  end

  describe "SecureHeaders#header_hash" do
    def expect_default_values(hash)
      expect(hash[XFO_HEADER_NAME]).to eq(SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE)
      expect(hash[XDO_HEADER_NAME]).to eq(SecureHeaders::XDownloadOptions::Constants::DEFAULT_VALUE)
      expect(hash[HSTS_HEADER_NAME]).to eq(SecureHeaders::StrictTransportSecurity::Constants::DEFAULT_VALUE)
      expect(hash[X_XSS_PROTECTION_HEADER_NAME]).to eq(SecureHeaders::XXssProtection::Constants::DEFAULT_VALUE)
      expect(hash[X_CONTENT_TYPE_OPTIONS_HEADER_NAME]).to eq(SecureHeaders::XContentTypeOptions::Constants::DEFAULT_VALUE)
      expect(hash[XPCDP_HEADER_NAME]).to eq(SecureHeaders::XPermittedCrossDomainPolicies::Constants::DEFAULT_VALUE)
    end

    it "produces a hash of headers given a hash as config" do
      hash = SecureHeaders::header_hash(:csp => {:default_src => %w('none'), :img_src => [SecureHeaders::ContentSecurityPolicy::DATA]})
      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
      expect_default_values(hash)
    end

    it "allows you to opt out of headers" do

    end

    it "validates your config upon configuration" do

    end

    it "works with nonces" do

    end

    it "produces a hash with a mix of config values, override values, and default values" do
      ::SecureHeaders::Configuration.configure do |config|
        config.hsts = { :max_age => '123456'}
        config.hpkp = {
          :enforce => true,
          :max_age => 1000000,
          :include_subdomains => true,
          :report_uri => '//example.com/uri-directive',
          :pins => [
            {:sha256 => 'abc'},
            {:sha256 => '123'}
          ]
        }
      end

      hash = SecureHeaders::header_hash(:csp => {:default_src => %w('none'), :img_src => [SecureHeaders::ContentSecurityPolicy::DATA]})
      ::SecureHeaders::Configuration.configure do |config|
        config.hsts = nil
        config.hpkp = SecureHeaders::OPT_OUT
      end

      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
      expect(hash[XFO_HEADER_NAME]).to eq(SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE)
      expect(hash[HSTS_HEADER_NAME]).to eq("max-age=123456")
      expect(hash[HPKP_HEADER_NAME]).to eq(%{max-age=1000000; pin-sha256="abc"; pin-sha256="123"; report-uri="//example.com/uri-directive"; includeSubDomains})
    end

    it "produces a hash of headers with default config" do
      hash = SecureHeaders::header_hash
      expect(hash['Content-Security-Policy-Report-Only']).to eq(SecureHeaders::ContentSecurityPolicy::Constants::DEFAULT_CSP_HEADER)
      expect_default_values(hash)
    end
  end
end
