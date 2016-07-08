require 'spec_helper'

module SecureHeaders
  describe SecureHeaders do
    before(:each) do
      reset_config
    end

    let(:request) { Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on") }

    it "raises a NotYetConfiguredError if default has not been set" do
      expect do
        SecureHeaders.header_hash_for(request)
      end.to raise_error(Configuration::NotYetConfiguredError)
    end

    it "raises a NotYetConfiguredError if trying to opt-out of unconfigured headers" do
      expect do
        SecureHeaders.opt_out_of_header(request, CSP::CONFIG_KEY)
      end.to raise_error(Configuration::NotYetConfiguredError)
    end

    it "raises and ArgumentError when referencing an override that has not been set" do
      expect do
        Configuration.default
        SecureHeaders.use_secure_headers_override(request, :missing)
      end.to raise_error(ArgumentError)
    end

    describe "#header_hash_for" do
      it "allows you to opt out of individual headers via API" do
        Configuration.default do |config|
          config.csp_report_only = { default_src: %w('self')} # no default value
        end
        SecureHeaders.opt_out_of_header(request, CSP::CONFIG_KEY)
        SecureHeaders.opt_out_of_header(request, CSP::REPORT_ONLY_CONFIG_KEY)
        SecureHeaders.opt_out_of_header(request, XContentTypeOptions::CONFIG_KEY)
        hash = SecureHeaders.header_hash_for(request)
        expect(hash['Content-Security-Policy-Report-Only']).to be_nil
        expect(hash['Content-Security-Policy']).to be_nil
        expect(hash['X-Content-Type-Options']).to be_nil
      end

      it "Carries options over when using overrides" do
        Configuration.default do |config|
          config.x_download_options = OPT_OUT
          config.x_permitted_cross_domain_policies = OPT_OUT
        end

        Configuration.override(:api) do |config|
          config.x_frame_options = OPT_OUT
        end

        SecureHeaders.use_secure_headers_override(request, :api)
        hash = SecureHeaders.header_hash_for(request)
        expect(hash['X-Download-Options']).to be_nil
        expect(hash['X-Permitted-Cross-Domain-Policies']).to be_nil
        expect(hash['X-Frame-Options']).to be_nil
      end

      it "allows you to opt out entirely" do
        Configuration.default
        SecureHeaders.opt_out_of_all_protection(request)
        hash = SecureHeaders.header_hash_for(request)
        ALL_HEADER_CLASSES.each do |klass|
          expect(hash[klass::CONFIG_KEY]).to be_nil
        end
        expect(hash.count).to eq(0)
      end

      it "allows you to override X-Frame-Options settings" do
        Configuration.default
        SecureHeaders.override_x_frame_options(request, XFrameOptions::DENY)
        hash = SecureHeaders.header_hash_for(request)
        expect(hash[XFrameOptions::HEADER_NAME]).to eq(XFrameOptions::DENY)
      end

      it "allows you to override opting out" do
        Configuration.default do |config|
          config.x_frame_options = OPT_OUT
          config.csp = OPT_OUT
        end

        SecureHeaders.override_x_frame_options(request, XFrameOptions::SAMEORIGIN)
        SecureHeaders.override_content_security_policy_directives(request, default_src: %w(https:), script_src: %w('self'))

        hash = SecureHeaders.header_hash_for(request)
        expect(hash[CSP::HEADER_NAME]).to eq("default-src https:; script-src 'self'")
        expect(hash[XFrameOptions::HEADER_NAME]).to eq(XFrameOptions::SAMEORIGIN)
      end

      it "produces a UA-specific CSP when overriding (and busting the cache)" do
        config = Configuration.default do |config|
          config.csp = {
            default_src: %w('self'),
            child_src: %w('self')
          }
        end
        firefox_request = Rack::Request.new(request.env.merge("HTTP_USER_AGENT" => USER_AGENTS[:firefox]))

        # append an unsupported directive
        SecureHeaders.override_content_security_policy_directives(firefox_request, plugin_types: %w(flash))
        # append a supported directive
        SecureHeaders.override_content_security_policy_directives(firefox_request, script_src: %w('self'))

        hash = SecureHeaders.header_hash_for(firefox_request)

        # child-src is translated to frame-src
        expect(hash[CSP::HEADER_NAME]).to eq("default-src 'self'; frame-src 'self'; script-src 'self'")
      end

      it "produces a hash of headers with default config" do
        Configuration.default
        hash = SecureHeaders.header_hash_for(request)
        expect_default_values(hash)
      end

      it "does not set the HSTS header if request is over HTTP" do
        plaintext_request = Rack::Request.new({})
        Configuration.default do |config|
          config.hsts = "max-age=123456"
        end
        expect(SecureHeaders.header_hash_for(plaintext_request)[StrictTransportSecurity::HEADER_NAME]).to be_nil
      end

      it "does not set the HPKP header if request is over HTTP" do
        plaintext_request = Rack::Request.new({})
        Configuration.default do |config|
          config.hpkp = {
            max_age: 1_000_000,
            include_subdomains: true,
            report_uri: '//example.com/uri-directive',
            pins: [
              { sha256: 'abc' },
              { sha256: '123' }
            ]
          }
        end

        expect(SecureHeaders.header_hash_for(plaintext_request)[PublicKeyPins::HEADER_NAME]).to be_nil
      end

      context "content security policy" do
        it "appends a value to csp directive" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self'),
              script_src: %w(mycdn.com 'unsafe-inline')
            }
          end

          SecureHeaders.append_content_security_policy_directives(request, script_src: %w(anothercdn.com))
          hash = SecureHeaders.header_hash_for(request)
          expect(hash[CSP::HEADER_NAME]).to eq("default-src 'self'; script-src mycdn.com 'unsafe-inline' anothercdn.com")
        end

        it "dups global configuration just once when overriding n times and only calls idempotent_additions? once per header" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self')
            }
          end

          expect(CSP).to receive(:idempotent_additions?).twice

          # before an override occurs, the env is empty
          expect(request.env[SECURE_HEADERS_CONFIG]).to be_nil

          SecureHeaders.append_content_security_policy_directives(request, script_src: %w(anothercdn.com))
          new_config = SecureHeaders.config_for(request)
          expect(new_config).to_not be(Configuration.get)

          SecureHeaders.override_content_security_policy_directives(request, script_src: %w(yet.anothercdn.com))
          current_config = SecureHeaders.config_for(request)
          expect(current_config).to be(new_config)

          SecureHeaders.header_hash_for(request)
        end

        it "doesn't allow you to muck with csp configs when a dynamic policy is in use" do
          default_config = Configuration.default
          expect { default_config.csp = {} }.to raise_error(NoMethodError)

          # config is frozen
          expect { default_config.send(:csp=, {}) }.to raise_error(RuntimeError)

          SecureHeaders.append_content_security_policy_directives(request, script_src: %w(anothercdn.com))
          new_config = SecureHeaders.config_for(request)
          expect { new_config.send(:csp=, {}) }.to raise_error(Configuration::IllegalPolicyModificationError)

          expect do
            new_config.instance_eval do
              new_config.csp = {}
            end
          end.to raise_error(Configuration::IllegalPolicyModificationError)
        end

        it "overrides individual directives" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self')
            }
          end
          SecureHeaders.override_content_security_policy_directives(request, default_src: %w('none'))
          hash = SecureHeaders.header_hash_for(request)
          expect(hash[CSP::HEADER_NAME]).to eq("default-src 'none'")
        end

        it "overrides non-existant directives" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self')
            }
          end
          SecureHeaders.override_content_security_policy_directives(request, img_src: [ContentSecurityPolicy::DATA_PROTOCOL])
          hash = SecureHeaders.header_hash_for(request)
          puts hash
          expect(hash[CSP::HEADER_NAME]).to eq("default-src https:; img-src data:")
        end

        it "does not append a nonce when the browser does not support it" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self'),
              script_src: %w(mycdn.com 'unsafe-inline'),
              style_src: %w('self')
            }
          end

          safari_request = Rack::Request.new(request.env.merge("HTTP_USER_AGENT" => USER_AGENTS[:safari5]))
          nonce = SecureHeaders.content_security_policy_script_nonce(safari_request)
          hash = SecureHeaders.header_hash_for(safari_request)
          expect(hash[CSP::HEADER_NAME]).to eq("default-src 'self'; script-src mycdn.com 'unsafe-inline'; style-src 'self'")
        end

        it "appends a nonce to the script-src when used" do
          Configuration.default do |config|
            config.csp = {
              default_src: %w('self'),
              script_src: %w(mycdn.com),
              style_src: %w('self')
            }
          end

          chrome_request = Rack::Request.new(request.env.merge("HTTP_USER_AGENT" => USER_AGENTS[:chrome]))
          nonce = SecureHeaders.content_security_policy_script_nonce(chrome_request)

          # simulate the nonce being used multiple times in a request:
          SecureHeaders.content_security_policy_script_nonce(chrome_request)
          SecureHeaders.content_security_policy_script_nonce(chrome_request)
          SecureHeaders.content_security_policy_script_nonce(chrome_request)

          hash = SecureHeaders.header_hash_for(chrome_request)
          expect(hash['Content-Security-Policy']).to eq("default-src 'self'; script-src mycdn.com 'nonce-#{nonce}'; style-src 'self'")
        end

        context "setting two headers" do
          it "sets identical values when the configs are the same" do
            Configuration.default do |config|
              config.csp = {
                default_src: %w('self')
              }
              config.csp_report_only = {
                default_src: %w('self')
              }
            end

            hash = SecureHeaders.header_hash_for(request)
            expect(hash['Content-Security-Policy']).to eq("default-src 'self'")
            expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'")
          end

          it "sets different headers when the configs are different" do
            Configuration.default do |config|
              config.csp = {
                default_src: %w('self')
              }
              config.csp_report_only = config.csp.merge({script_src: %w('self')})
            end

            hash = SecureHeaders.header_hash_for(request)
            expect(hash['Content-Security-Policy']).to eq("default-src 'self'")
            expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src 'self'")
          end

          it "allows appending to the enforced policy" do
            Configuration.default do |config|
              config.csp = {
                default_src: %w('self')
              }
              config.csp_report_only = config.csp
            end

            SecureHeaders.append_content_security_policy_directives(request, {script_src: %w(anothercdn.com)}, :enforced)
            hash = SecureHeaders.header_hash_for(request)
            expect(hash['Content-Security-Policy']).to eq("default-src 'self'; script-src 'self' anothercdn.com")
            expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'")
          end

          it "allows appending to the report only policy" do
            Configuration.default do |config|
              config.csp = {
                default_src: %w('self')
              }
              config.csp_report_only = config.csp
            end

            SecureHeaders.append_content_security_policy_directives(request, {script_src: %w(anothercdn.com)}, :report_only)
            hash = SecureHeaders.header_hash_for(request)
            expect(hash['Content-Security-Policy']).to eq("default-src 'self'")
            expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src 'self' anothercdn.com")
          end

          it "allows appending to both policies" do
            Configuration.default do |config|
              config.csp = {
                default_src: %w('self')
              }
              config.csp_report_only = config.csp
            end

            SecureHeaders.append_content_security_policy_directives(request, {script_src: %w(anothercdn.com)}, :both)
            hash = SecureHeaders.header_hash_for(request)
            expect(hash['Content-Security-Policy']).to eq("default-src 'self'; script-src 'self' anothercdn.com")
            expect(hash['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; script-src 'self' anothercdn.com")
          end
          it "allows overriding the enforced policy"
          it "allows overriding the report only policy"
          it "allows overriding both policies"
        end
      end
    end

    context "validation" do
      it "validates your hsts config upon configuration" do
        expect do
          Configuration.default do |config|
            config.hsts = 'lol'
          end
        end.to raise_error(STSConfigError)
      end

      it "validates your csp config upon configuration" do
        expect do
          Configuration.default do |config|
            config.csp = { CSP::DEFAULT_SRC => '123456' }
          end
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "raises errors for unknown directives" do
        expect do
          Configuration.default do |config|
            config.csp = { made_up_directive: '123456' }
          end
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "validates your xfo config upon configuration" do
        expect do
          Configuration.default do |config|
            config.x_frame_options = "NOPE"
          end
        end.to raise_error(XFOConfigError)
      end

      it "validates your xcto config upon configuration" do
        expect do
          Configuration.default do |config|
            config.x_content_type_options = "lol"
          end
        end.to raise_error(XContentTypeOptionsConfigError)
      end

      it "validates your x_xss config upon configuration" do
        expect do
          Configuration.default do |config|
            config.x_xss_protection = "lol"
          end
        end.to raise_error(XXssProtectionConfigError)
      end

      it "validates your xdo config upon configuration" do
        expect do
          Configuration.default do |config|
            config.x_download_options = "lol"
          end
        end.to raise_error(XDOConfigError)
      end

      it "validates your x_permitted_cross_domain_policies config upon configuration" do
        expect do
          Configuration.default do |config|
            config.x_permitted_cross_domain_policies = "lol"
          end
        end.to raise_error(XPCDPConfigError)
      end

      it "validates your referrer_policy config upon configuration" do
        expect do
          Configuration.default do |config|
            config.referrer_policy = "lol"
          end
        end.to raise_error(ReferrerPolicyConfigError)
      end

      it "validates your hpkp config upon configuration" do
        expect do
          Configuration.default do |config|
            config.hpkp = "lol"
          end
        end.to raise_error(PublicKeyPinsConfigError)
      end

      it "validates your cookies config upon configuration" do
        expect do
          Configuration.default do |config|
            config.cookies = { secure: "lol" }
          end
        end.to raise_error(CookiesConfigError)
      end
    end
  end
end
