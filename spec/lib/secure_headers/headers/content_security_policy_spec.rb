require 'spec_helper'

module SecureHeaders
  describe ContentSecurityPolicy do
    let(:default_opts) do
      {
        :disable_fill_missing => true,
        :default_src => 'https://*',
        :report_uri => '/csp_report',
        :script_src => 'inline eval https://* data:',
        :style_src => "inline https://* about:"
      }
    end

    IE = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    FIREFOX = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.2) Gecko/20121223 Ubuntu/9.25 (jaunty) Firefox/3.8"
    FIREFOX_23 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0"
    CHROME = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"
    CHROME_25 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"


    def request_for user_agent, request_uri=nil, options={:ssl => false}
      double(:ssl? => options[:ssl], :env => {'HTTP_USER_AGENT' => user_agent}, :url => (request_uri || 'http://areallylongdomainexample.com') )
    end

    before(:each) do
      @options_with_forwarding = default_opts.merge(:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com')
    end

    describe "#name" do
      context "when supplying options to override request" do
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => IE).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => FIREFOX).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => FIREFOX_23).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => CHROME).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => CHROME_25).name).to eq(HEADER_NAME + "-Report-Only")}
      end

      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(IE)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX_23)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME_25)).name).to eq(HEADER_NAME + "-Report-Only")}
      end

      context "when in enforce mode" do
        let(:opts) { default_opts.merge(:enforce => true)}

        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(IE)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX_23)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(CHROME)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(CHROME_25)).name).to eq(HEADER_NAME)}
      end
    end

    describe "#normalize_csp_options" do
      before(:each) do
        default_opts.delete(:disable_fill_missing)
        default_opts[:script_src] << ' self none'
        @opts = default_opts
      end

      context "Content-Security-Policy" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(@opts, :request => request_for(CHROME))
          expect(csp.value).to include("script-src 'unsafe-inline' 'unsafe-eval' https://* data: 'self' 'none'")
        end

        it "adds a @enforce and @app_name variables to the report uri" do
          opts = @opts.merge(:tag_report_uri => true, :enforce => true, :app_name => 'twitter')
          csp = ContentSecurityPolicy.new(opts, :request => request_for(CHROME))
          expect(csp.value).to include("/csp_report?enforce=true&app_name=twitter")
        end

        it "does not add an empty @app_name variable to the report uri" do
          opts = @opts.merge(:tag_report_uri => true, :enforce => true)
          csp = ContentSecurityPolicy.new(opts, :request => request_for(CHROME))
          expect(csp.value).to include("/csp_report?enforce=true")
        end

        it "accepts procs for report-uris" do
          opts = {
            :default_src => 'self',
            :report_uri => lambda { "http://lambda/result" }
          }

          csp = ContentSecurityPolicy.new(opts)
          expect(csp.value).to match("report-uri http://lambda/result")
        end

        it "accepts procs for other fields" do
          opts = {
            :default_src => lambda { "http://lambda/result" },
            :enforce => lambda { true },
            :disable_fill_missing => lambda { true }
          }

          csp = ContentSecurityPolicy.new(opts)
          expect(csp.value).to eq("default-src http://lambda/result; img-src http://lambda/result data:;")
          expect(csp.name).to match("Content-Security-Policy")
        end
      end
    end

    describe "#value" do
      it "raises an exception when default-src is missing" do
        csp = ContentSecurityPolicy.new({:script_src => 'anything'}, :request => request_for(CHROME))
        expect {
          csp.value
        }.to raise_error(RuntimeError)
      end

      context "auto-whitelists data: uris for img-src" do
        it "sets the value if no img-src specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :disable_fill_missing => true}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self' data:;")
        end

        it "appends the value if img-src is specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :img_src => 'self', :disable_fill_missing => true}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self' data:;")
        end
      end

      it "fills in directives without values with default-src value" do
        options = default_opts.merge(:disable_fill_missing => false)
        csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
        value = "default-src https://*; connect-src https://*; font-src https://*; frame-src https://*; img-src https://* data:; media-src https://*; object-src https://*; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;"
        expect(csp.value).to eq(value)
      end

      it "sends the standard csp header if an unknown browser is supplied" do
        csp = ContentSecurityPolicy.new(default_opts, :request => request_for(IE))
        expect(csp.value).to match "default-src"
      end

      context "Firefox" do
        it "builds a csp header for firefox" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX))
          expect(csp.value).to eq("default-src https://*; img-src https://* data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;")
        end
      end

      context "Chrome" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src https://*; img-src https://* data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;")
        end

        it "ignores :forward_endpoint settings" do
          csp = ContentSecurityPolicy.new(@options_with_forwarding, :request => request_for(CHROME))
          expect(csp.value).to match(/report-uri #{@options_with_forwarding[:report_uri]};/)
        end
      end

      context "when using a nonce" do
        it "adds a nonce and unsafe-inline to the script-src value" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "self nonce"), :request => request_for(CHROME))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds a nonce and unsafe-inline to the style-src value" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => "self nonce"), :request => request_for(CHROME))
          expect(header.value).to include("style-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds an identical nonce to the style and script-src directives" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => "self nonce", :script_src => "self nonce"), :request => request_for(CHROME))
          nonce = header.nonce
          value = header.value
          expect(value).to include("style-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
          expect(value).to include("script-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
        end

        it "does not add 'unsafe-inline' twice" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "self nonce inline"), :request => request_for(CHROME))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline';")
        end
      end

      context "when supplying additional http directive values" do
        let(:options) {
          default_opts.merge({
            :http_additions => {
              :frame_src => "http://*",
              :img_src => "http://*"
            }
          })
        }

        it "adds directive values for headers on http" do
          csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src https://*; frame-src http://*; img-src http://* data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;")
        end

        it "does not add the directive values if requesting https" do
          csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME, '/', :ssl => true))
          expect(csp.value).not_to match(/http:/)
        end

        it "does not add the directive values if requesting https" do
          csp = ContentSecurityPolicy.new(options, :ua => "Chrome", :ssl => true)
          expect(csp.value).not_to match(/http:/)
        end
      end
    end
  end
end
