require 'spec_helper'

describe SecureHeaders do
  after(:each) do
    reset_config
  end

  def stub_user_agent val
    allow(request).to receive_message_chain(:env, :[]).and_return(val)
  end

  def reset_config
    ::SecureHeaders::Configuration.configure do |config|
      config.hpkp = SecureHeaders::OPT_OUT
      config.hsts = nil
      config.x_frame_options = nil
      config.x_content_type_options = nil
      config.x_xss_protection = nil
      config.csp = nil
      config.x_download_options = nil
      config.x_permitted_cross_domain_policies = nil
    end
  end

  it "does not set the HSTS header if request is over HTTP" do
    ::SecureHeaders::Configuration.configure do |config|
      config.hsts = { :max_age => '123456'}
    end
    expect(SecureHeaders::header_hash(ssl: false)[HSTS_HEADER_NAME]).to be_nil
  end

  it "does not set the HPKP header if request is over HTTP" do
    ::SecureHeaders::Configuration.configure do |config|
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

    expect(SecureHeaders::header_hash(ssl: false)[HPKP_HEADER_NAME]).to be_nil
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
      hash = SecureHeaders::header_hash(ssl: true, csp: {default_src: %w('none'), img_src: [SecureHeaders::ContentSecurityPolicy::DATA]})
      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
      expect_default_values(hash)
    end

    it "allows you to opt out of headers" do
      hash = SecureHeaders::header_hash(csp: SecureHeaders::OPT_OUT)
      expect(hash['Content-Security-Policy-Report-Only']).to be_nil
      expect(hash['Content-Security-Policy']).to be_nil
    end

    it "appends a nonce to the script-src/style-src when used" do
      ::SecureHeaders::Configuration.configure do |config|
        config.csp = {
          :default_src => %w('self'),
          :script_src => %w(mycdn.com)
        }
      end
      env = {"HTTP_USER_AGENT" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"}
      nonce = SecureHeaders::content_security_policy_nonce(env)
      hash = SecureHeaders::header_hash(env)
      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src mycdn.com 'nonce-#{nonce}' 'unsafe-inline'")

      env = {"HTTP_USER_AGENT" => "Mozilla/4.0 totally a legit browser"}
      hash = SecureHeaders::header_hash(env)
      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src mycdn.com 'unsafe-inline'")
    end

    it "validates your hsts config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.hsts = 'lol'
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::STSConfigError)
    end

    it "validates your csp config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.csp = { SecureHeaders::CSP::DEFAULT_SRC => '123456'}
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::ContentSecurityPolicyConfigError)
    end

    it "validates your xfo config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.x_frame_options = "NOPE"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::XFOConfigError)
    end

    it "validates your xcto config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.x_content_type_options = "lol"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::XContentTypeOptionsConfigError)
    end

    it "validates your x_xss config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.x_xss_protection = "lol"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::XXssProtectionConfigError)
    end

    it "validates your xdo config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.x_download_options = "lol"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::XDOConfigError)
    end

    it "validates your x_permitted_cross_domain_policies config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.x_permitted_cross_domain_policies = "lol"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::XPCDPConfigError)
    end

    it "validates your hpkp config upon configuration" do
      expect {
        ::SecureHeaders::Configuration.configure do |config|
          config.hpkp = "lol"
        end
        ::SecureHeaders::Configuration.validate_config!
      }.to raise_error(SecureHeaders::PublicKeyPinsConfigError)
    end

    it "produces a hash with a mix of config values, override values, and default values" do
      ::SecureHeaders::Configuration.configure do |config|
        config.hsts = "max-age=123456"
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

      hash = SecureHeaders::header_hash(ssl: true, :csp => {:default_src => %w('none'), :img_src => [SecureHeaders::ContentSecurityPolicy::DATA]})
      expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
      expect(hash[XFO_HEADER_NAME]).to eq(SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE)
      expect(hash[HSTS_HEADER_NAME]).to eq("max-age=123456")
      expect(hash[HPKP_HEADER_NAME]).to eq(%{max-age=1000000; pin-sha256="abc"; pin-sha256="123"; report-uri="//example.com/uri-directive"; includeSubDomains})
    end

    it "produces a hash of headers with default config" do
      hash = SecureHeaders::header_hash(ssl: true)
      expect(hash['Content-Security-Policy-Report-Only']).to eq(SecureHeaders::ContentSecurityPolicy::Constants::DEFAULT_CSP_HEADER)
      expect_default_values(hash)
    end
  end
end
