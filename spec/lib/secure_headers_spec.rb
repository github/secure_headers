require 'spec_helper'

describe SecureHeaders do
  before(:each) do
    @request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
  end

  it "uses cached headers when no overrides are present" do
    SecureHeaders::Configuration.configure do |config|
      config.x_frame_options = "DENY"
    end
    SecureHeaders::ALL_HEADER_CLASSES.each do |klass|
      expect(klass).not_to receive(:make_header)
    end

    SecureHeaders::header_hash_for(@request)
  end

  it "uses generates new headers when values are overridden" do
    SecureHeaders::Configuration.configure do |config|
      config.x_frame_options = "DENY"
    end
    (SecureHeaders::ALL_HEADER_CLASSES - [SecureHeaders::ContentSecurityPolicy]).each do |klass|
      expect(klass).not_to receive(:make_header)
    end
    expect(SecureHeaders::ContentSecurityPolicy).to receive(:make_header)

    SecureHeaders::override_content_security_policy_directives(@request, default_src: %w('none'))
    SecureHeaders::header_hash_for(@request)
  end

  context "dynamic config" do
    before(:each) do
      reset_config
    end

    def reset_config
      SecureHeaders::Configuration.configure do |config|
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
      SecureHeaders::Configuration.configure do |config|
        config.hsts = "max-age=123456"
      end
      expect(SecureHeaders::header_hash_for(Rack::Request.new({}))[SecureHeaders::StrictTransportSecurity::HEADER_NAME]).to be_nil
    end

    it "does not set the HPKP header if request is over HTTP" do
      SecureHeaders::Configuration.configure do |config|
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

      expect(SecureHeaders::header_hash_for(Rack::Request.new({}))[SecureHeaders::PublicKeyPins::HEADER_NAME]).to be_nil
    end

    describe "SecureHeaders#header_hash_for" do
      def expect_default_values(hash)
        expect(hash[SecureHeaders::XFrameOptions::HEADER_NAME]).to eq(SecureHeaders::XFrameOptions::DEFAULT_VALUE)
        expect(hash[SecureHeaders::XDownloadOptions::HEADER_NAME]).to eq(SecureHeaders::XDownloadOptions::DEFAULT_VALUE)
        expect(hash[SecureHeaders::StrictTransportSecurity::HEADER_NAME]).to eq(SecureHeaders::StrictTransportSecurity::DEFAULT_VALUE)
        expect(hash[SecureHeaders::XXssProtection::HEADER_NAME]).to eq(SecureHeaders::XXssProtection::DEFAULT_VALUE)
        expect(hash[SecureHeaders::XContentTypeOptions::HEADER_NAME]).to eq(SecureHeaders::XContentTypeOptions::DEFAULT_VALUE)
        expect(hash[SecureHeaders::XPermittedCrossDomainPolicies::HEADER_NAME]).to eq(SecureHeaders::XPermittedCrossDomainPolicies::DEFAULT_VALUE)
      end

      it "produces a hash of headers given a hash as config" do
        SecureHeaders::override_content_security_policy_directives(@request, default_src: %w('none'), img_src: [SecureHeaders::ContentSecurityPolicy::DATA])
        hash = SecureHeaders::header_hash_for(@request)
        expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
        expect_default_values(hash)
      end

      it "allows you to opt out of headers" do
        SecureHeaders::opt_out_of(@request, SecureHeaders::CSP::CONFIG_KEY)
        hash = SecureHeaders::header_hash_for(@request)
        expect(hash['Content-Security-Policy-Report-Only']).to be_nil
        expect(hash['Content-Security-Policy']).to be_nil
      end

      it "appends a nonce to the script-src/style-src when used" do
        SecureHeaders::Configuration.configure do |config|
          config.csp = {
            :default_src => %w('self'),
            :script_src => %w(mycdn.com 'unsafe-inline')
          }
        end

        request = Rack::Request.new(@request.env.merge("HTTP_USER_AGENT" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"))
        nonce = SecureHeaders::content_security_policy_nonce(request)
        hash = SecureHeaders::header_hash_for(request)
        expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src mycdn.com 'unsafe-inline' 'nonce-#{nonce}'")
      end

      it "does not append a nonce when the browser does not support it" do
        SecureHeaders::Configuration.configure do |config|
          config.csp = {
            :default_src => %w('self'),
            :script_src => %w(mycdn.com 'unsafe-inline')
          }
        end
        env = {"HTTP_USER_AGENT" => "Mozilla/4.0 totally a legit browser"}
        hash = SecureHeaders::header_hash_for(@request)
        expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src mycdn.com 'unsafe-inline'")
      end

      it "produces a hash with a mix of config values, override values, and default values" do
        SecureHeaders::Configuration.configure do |config|
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

        SecureHeaders::override_content_security_policy_directives(@request, :default_src => %w('none'), :img_src => [SecureHeaders::ContentSecurityPolicy::DATA])
        hash = SecureHeaders::header_hash_for(@request)
        expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'none'; img-src data:")
        expect(hash[SecureHeaders::XFrameOptions::HEADER_NAME]).to eq(SecureHeaders::XFrameOptions::DEFAULT_VALUE)
        expect(hash[SecureHeaders::StrictTransportSecurity::HEADER_NAME]).to eq("max-age=123456")
        expect(hash[SecureHeaders::PublicKeyPins::HEADER_NAME]).to eq(%{max-age=1000000; pin-sha256="abc"; pin-sha256="123"; report-uri="//example.com/uri-directive"; includeSubDomains})
      end

      it "produces a hash of headers with default config" do
        hash = SecureHeaders::header_hash_for(@request)
        expect(hash['Content-Security-Policy-Report-Only']).to eq(SecureHeaders::ContentSecurityPolicy::DEFAULT_CSP_HEADER)
        expect_default_values(hash)
      end

      it "validates your hsts config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.hsts = 'lol'
          end
        }.to raise_error(SecureHeaders::STSConfigError)
      end

      it "validates your csp config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.csp = { SecureHeaders::CSP::DEFAULT_SRC => '123456'}
          end
        }.to raise_error(SecureHeaders::ContentSecurityPolicyConfigError)
      end

      it "validates your xfo config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.x_frame_options = "NOPE"
          end
        }.to raise_error(SecureHeaders::XFOConfigError)
      end

      it "validates your xcto config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.x_content_type_options = "lol"
          end
        }.to raise_error(SecureHeaders::XContentTypeOptionsConfigError)
      end

      it "validates your x_xss config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.x_xss_protection = "lol"
          end
        }.to raise_error(SecureHeaders::XXssProtectionConfigError)
      end

      it "validates your xdo config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.x_download_options = "lol"
          end
        }.to raise_error(SecureHeaders::XDOConfigError)
      end

      it "validates your x_permitted_cross_domain_policies config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.x_permitted_cross_domain_policies = "lol"
          end
        }.to raise_error(SecureHeaders::XPCDPConfigError)
      end

      it "validates your hpkp config upon configuration" do
        expect {
          SecureHeaders::Configuration.configure do |config|
            config.hpkp = "lol"
          end
        }.to raise_error(SecureHeaders::PublicKeyPinsConfigError)
      end
    end

    it "caches default header values at configure time" do
      SecureHeaders::Configuration.configure do |config|
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
        config.hsts = "max-age=11111111; includeSubDomains; preload"
        config.x_frame_options = "DENY"
        config.x_content_type_options = "nosniff"
        config.x_xss_protection = "1; mode=block"
        config.csp = {
          default_src: %w('self'),
          # intentionally use a directive that is not supported by all browsers
          child_src: %w('self'),
          object_src: %w(pleasedontwhitelistflashever.com),
          enforce: true
        }
        config.x_download_options = SecureHeaders::OPT_OUT
        config.x_permitted_cross_domain_policies = SecureHeaders::OPT_OUT
      end

      hash = SecureHeaders::Configuration::default_headers
      expect(hash[SecureHeaders::XFrameOptions::CONFIG_KEY]).to eq([SecureHeaders::XFrameOptions::HEADER_NAME, "DENY"])
      expect(hash[SecureHeaders::XDownloadOptions::CONFIG_KEY]).to be_nil
      expect(hash[SecureHeaders::StrictTransportSecurity::CONFIG_KEY]).to eq([SecureHeaders::StrictTransportSecurity::HEADER_NAME, "max-age=11111111; includeSubDomains; preload"])
      expect(hash[SecureHeaders::XXssProtection::CONFIG_KEY]).to eq([SecureHeaders::XXssProtection::HEADER_NAME, "1; mode=block"])
      expect(hash[SecureHeaders::XContentTypeOptions::CONFIG_KEY]).to eq([SecureHeaders::XContentTypeOptions::HEADER_NAME, "nosniff"])
      expect(hash[SecureHeaders::XPermittedCrossDomainPolicies::CONFIG_KEY]).to be_nil
      expect(hash[SecureHeaders::PublicKeyPins::CONFIG_KEY]).to eq([SecureHeaders::PublicKeyPins::HEADER_NAME, %(max-age=1000000; pin-sha256="abc"; pin-sha256="123"; report-uri="//example.com/uri-directive"; includeSubDomains)])
      SecureHeaders::CSP::VARIATIONS.each do |name, _|
        expected = if ["Chrome", "Opera"].include?(name)
          "default-src 'self'; child-src 'self'; object-src pleasedontwhitelistflashever.com"
        else
          "default-src 'self'; object-src pleasedontwhitelistflashever.com"
        end
        expect(hash[SecureHeaders::ContentSecurityPolicy::CONFIG_KEY][name]).to eq([SecureHeaders::ContentSecurityPolicy::HEADER_NAME, expected])
      end
    end
  end
end
