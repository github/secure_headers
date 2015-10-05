require 'spec_helper'

module SecureHeaders
  describe ContentSecurityPolicy do
    let(:default_opts) do
      {
        :default_src => 'https:',
        :img_src => "https: data:",
        :script_src => "'unsafe-inline' 'unsafe-eval' https: data:",
        :style_src => "'unsafe-inline' https: about:",
        :report_uri => '/csp_report'
      }
    end
    let(:controller) { DummyClass.new }

    IE = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    FIREFOX = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.2) Gecko/20121223 Ubuntu/9.25 (jaunty) Firefox/3.8"
    FIREFOX_23 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0"
    CHROME = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"
    CHROME_25 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"
    SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
    OPERA = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16"

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

    it "exports a policy to JSON" do
      policy = ContentSecurityPolicy.new(default_opts)
      puts default_opts
      expected = %({"default-src":["https:"],"img-src":["https:","data:"],"script-src":["'unsafe-inline'","'unsafe-eval'","https:","data:"],"style-src":["'unsafe-inline'","https:","about:"],"report-uri":["/csp_report"]})
      expect(policy.to_json).to eq(expected)
    end

    it "imports JSON to build a policy" do
      json1 = %({"default-src":["https:"],"script-src":["'unsafe-inline'","'unsafe-eval'","https:","data:"]})
      json2 = %({"style-src":["'unsafe-inline'"],"img-src":["https:","data:"]})
      json3 = %({"style-src":["https:","about:"]})
      config = ContentSecurityPolicy.from_json(json1, json2, json3)
      policy = ContentSecurityPolicy.new(config)

      expected = %({"default-src":["https:"],"script-src":["'unsafe-inline'","'unsafe-eval'","https:","data:"],"style-src":["'unsafe-inline'","https:","about:"],"img-src":["https:","data:"]})
      expect(policy.to_json).to eq(expected)
    end

    context "when using hash sources" do
      it "adds hashes and unsafe-inline to the script-src" do
        policy = ContentSecurityPolicy.new(default_opts.merge(:script_hashes => ['sha256-abc123']))
        expect(policy.value).to match /script-src[^;]*'sha256-abc123'/
      end
    end

    describe "#normalize_csp_options" do
      before(:each) do
        default_opts[:script_src] <<  " 'self' 'none'"
        @opts = default_opts
      end

      context "Content-Security-Policy" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(@opts, :request => request_for(CHROME))
          expect(csp.value).to include("script-src 'unsafe-inline' 'unsafe-eval' https: data: 'self' 'none'")
        end

        it "adds a @enforce and @app_name variables to the report uri" do
          opts = @opts.merge(:tag_report_uri => true, :enforce => true, :app_name => proc { 'twitter' })
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
            :default_src => "'self'",
            :report_uri => proc { "http://lambda/result" }
          }

          csp = ContentSecurityPolicy.new(opts)
          expect(csp.value).to match("report-uri http://lambda/result")
        end

        it "accepts procs for other fields" do
          opts = {
            :default_src => proc { "http://lambda/result" },
            :enforce => proc { true },
          }

          csp = ContentSecurityPolicy.new(opts)
          expect(csp.value).to eq("default-src http://lambda/result; img-src http://lambda/result data:;")
          expect(csp.name).to match("Content-Security-Policy")
        end

        it "passes a reference to the controller to the proc" do
          controller = double
          user = double(:beta_testing? => true)

          allow(controller).to receive(:current_user).and_return(user)
          opts = {
            :default_src => "'self'",
            :enforce => lambda { |c| c.current_user.beta_testing? }
          }
          csp = ContentSecurityPolicy.new(opts, :controller => controller)
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
          csp = ContentSecurityPolicy.new({:default_src => "'self'"}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self' data:;")
        end

        it "appends the value if img-src is specified" do
          csp = ContentSecurityPolicy.new({:default_src => "'self'", :img_src => "'self'"}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self' data:;")
        end

        it "doesn't add a duplicate data uri if img-src specifies it already" do
          csp = ContentSecurityPolicy.new({:default_src => "'self'", :img_src => "'self' data:"}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self' data:;")
        end

        it "allows the user to disable img-src data: uris auto-whitelisting" do
          csp = ContentSecurityPolicy.new({:default_src => "'self'", :img_src => "'self'", :disable_img_src_data_uri => true}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src 'self';")
        end
      end

      it "sends the standard csp header if an unknown browser is supplied" do
        csp = ContentSecurityPolicy.new(default_opts, :request => request_for(IE))
        expect(csp.value).to match "default-src"
      end

      context "Firefox" do
        it "builds a csp header for firefox" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX))
          expect(csp.value).to eq("default-src https:; img-src https: data:; script-src 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'unsafe-inline' https: about:; report-uri /csp_report;")
        end
      end

      context "Chrome" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src https:; img-src https: data:; script-src 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'unsafe-inline' https: about:; report-uri /csp_report;")
        end
      end

      context "when using a nonce" do
        it "adds a nonce and unsafe-inline to the script-src value when using chrome" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce"), :request => request_for(CHROME), :controller => controller)
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds a nonce and unsafe-inline to the script-src value when using firefox" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce"), :request => request_for(FIREFOX), :controller => controller)
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds a nonce and unsafe-inline to the script-src value when using opera" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce"), :request => request_for(OPERA), :controller => controller)
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "does not add a nonce and unsafe-inline to the script-src value when using Safari" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce"), :request => request_for(SAFARI), :controller => controller)
          expect(header.value).to include("script-src 'self' 'unsafe-inline'")
          expect(header.value).not_to include("nonce")
        end

        it "does not add a nonce and unsafe-inline to the script-src value when using IE" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce"), :request => request_for(IE), :controller => controller)
          expect(header.value).to include("script-src 'self' 'unsafe-inline'")
          expect(header.value).not_to include("nonce")
        end

        it "adds a nonce and unsafe-inline to the style-src value" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => "'self' nonce"), :request => request_for(CHROME), :controller => controller)
          expect(header.value).to include("style-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds an identical nonce to the style and script-src directives" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => "'self' nonce", :script_src => "'self' nonce"), :request => request_for(CHROME), :controller => controller)
          nonce = header.nonce
          value = header.value
          expect(value).to include("style-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
          expect(value).to include("script-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
        end

        it "does not add 'unsafe-inline' twice" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => "'self' nonce 'unsafe-inline'"), :request => request_for(CHROME), :controller => controller)
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline';")
        end
      end

      context "when supplying additional http directive values" do
        let(:options) {
          default_opts.merge({
            :http_additions => {
              :frame_src => "http:",
              :img_src => "http:"
            }
          })
        }

        it "adds directive values for headers on http" do
          csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src https:; frame-src http:; img-src http: data:; script-src 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'unsafe-inline' https: about:; report-uri /csp_report;")
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

      describe "class methods" do
        let(:ua) { CHROME }
        let(:env) do
          double.tap do |env|
            allow(env).to receive(:[]).with('HTTP_USER_AGENT').and_return(ua)
          end
        end
        let(:request) do
          double(
            :ssl? => true,
            :url => 'https://example.com',
            :env => env
          )
        end

        describe ".add_to_env" do
          let(:controller) { double }
          let(:config) { {:default_src => "'self'"} }
          let(:options) { {:controller => controller} }

          it "adds metadata to env" do
            metadata = {
              :config => config,
              :options => options
            }
            expect(ContentSecurityPolicy).to receive(:options_from_request).and_return(options)
            expect(env).to receive(:[]=).with(ContentSecurityPolicy::ENV_KEY, metadata)
            ContentSecurityPolicy.add_to_env(request, controller, config)
          end
        end

        describe ".options_from_request" do
          it "extracts options from request" do
            options = ContentSecurityPolicy.options_from_request(request)
            expect(options).to eql({
              :ua => ua,
              :ssl => true,
              :request_uri => 'https://example.com'
            })
          end
        end
      end
    end
  end
end
