require 'spec_helper'

module SecureHeaders
  describe ContentSecurityPolicy do
    let(:default_opts) do
      {
        :default_src => %w(https:),
        :img_src => %w(https: data:),
        :script_src => %w('unsafe-inline' 'unsafe-eval' https: data:),
        :style_src => %w('unsafe-inline' https: about:),
        :report_uri => %w(/csp_report),
        :ua => CHROME_25
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
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: IE)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: FIREFOX)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: FIREFOX_23)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: CHROME)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: CHROME_25)).name).to eq(HEADER_NAME + "-Report-Only")}
      end

      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: IE)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: FIREFOX)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: FIREFOX_23)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: CHROME)).name).to eq(HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(ua: CHROME_25)).name).to eq(HEADER_NAME + "-Report-Only")}
      end

      context "when in enforce mode" do
        let(:opts) { default_opts.merge(:enforce => true)}

        specify { expect(ContentSecurityPolicy.new(opts.merge(ua: IE)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts.merge(ua: FIREFOX)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts.merge(ua: FIREFOX_23)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts.merge(ua: CHROME)).name).to eq(HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts.merge(ua: CHROME_25)).name).to eq(HEADER_NAME)}
      end
    end

    it "exports a policy to JSON" do
      policy = ContentSecurityPolicy.new(default_opts)
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

    describe "#normalize_csp_options" do
      before(:each) do
        default_opts[:script_src] +=  %w('self' 'none')
        @opts = default_opts
      end

      context "Content-Security-Policy" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(@opts.merge(ua: CHROME))
          expect(csp.value).to include("script-src 'unsafe-inline' 'unsafe-eval' https: data: 'self'")
        end

        it "adds a @enforce and @app_name variables to the report uri" do
          opts = @opts.merge(:tag_report_uri => true, :enforce => true, :app_name => 'twitter')
          csp = ContentSecurityPolicy.new(opts.merge(ua: CHROME))
          expect(csp.value).to include("/csp_report?enforce=true&app_name=twitter")
        end

        it "does not add an empty @app_name variable to the report uri" do
          opts = @opts.merge(:tag_report_uri => true, :enforce => true)
          csp = ContentSecurityPolicy.new(opts.merge(ua: CHROME))
          expect(csp.value).to include("/csp_report?enforce=true")
        end
      end
    end

    describe "#value" do
      context "browser sniffing" do
        let(:complex_opts) do
          ALL_DIRECTIVES.inject({}) { |memo, directive| memo[directive] = %w('self'); memo }.merge(:block_all_mixed_content => '')
        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: CHROME))
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self'; style-src 'self'; block-all-mixed-content; report-uri 'self'")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: FIREFOX))
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self'; style-src 'self'; report-uri 'self'")
        end

        it "filters base-uri, blocked-all-mixed-content, child-src, form-action, frame-ancestors, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: SAFARI))
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self'; style-src 'self'; report-uri 'self'")
        end
      end

      it "raises an exception when default-src is missing" do
        expect {
          csp = ContentSecurityPolicy.new({:script_src => %w('anything')}.merge(ua: CHROME))
          csp.value
        }.to raise_error(ArgumentError)
      end


      it "sends the standard csp header if an unknown browser is supplied" do
        csp = ContentSecurityPolicy.new(default_opts.merge(ua: IE))
        expect(csp.value).to match "default-src"
      end

      context "Firefox" do
        it "builds a csp header for firefox" do
          csp = ContentSecurityPolicy.new(default_opts.merge(ua: FIREFOX))
          expect(csp.value).to eq("default-src https:; img-src https: data:; script-src 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'unsafe-inline' https: about:; report-uri /csp_report")
        end
      end

      context "Chrome" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(default_opts.merge(ua: CHROME))
          expect(csp.value).to eq("default-src https:; img-src https: data:; script-src 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'unsafe-inline' https: about:; report-uri /csp_report")
        end
      end

      context "when using a nonce" do
        it "adds a nonce and unsafe-inline to the script-src value when using chrome" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce)).merge(ua: CHROME))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds a nonce and unsafe-inline to the script-src value when using firefox" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce)).merge(ua: FIREFOX))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds a nonce and unsafe-inline to the script-src value when using opera" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce)).merge(ua: OPERA))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "does not add a nonce and unsafe-inline to the script-src value when using Safari" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce)).merge(ua: SAFARI))
          expect(header.value).to include("script-src 'self' 'unsafe-inline'")
          expect(header.value).not_to include("nonce")
        end

        it "does not add a nonce and unsafe-inline to the script-src value when using IE" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce)).merge(ua: IE))
          expect(header.value).to include("script-src 'self' 'unsafe-inline'")
          expect(header.value).not_to include("nonce")
        end

        it "adds a nonce and unsafe-inline to the style-src value" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => %w('self' nonce)).merge(ua: CHROME))
          expect(header.value).to include("style-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline'")
        end

        it "adds an identical nonce to the style and script-src directives" do
          header = ContentSecurityPolicy.new(default_opts.merge(:style_src => %w('self' nonce), :script_src => %w('self' nonce)).merge(ua: CHROME))
          nonce = header.nonce
          value = header.value
          expect(value).to include("style-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
          expect(value).to include("script-src 'self' 'nonce-#{nonce}' 'unsafe-inline'")
        end

        it "does not add 'unsafe-inline' twice" do
          header = ContentSecurityPolicy.new(default_opts.merge(:script_src => %w('self' nonce 'unsafe-inline'), ua: CHROME))
          expect(header.value).to include("script-src 'self' 'nonce-#{header.nonce}' 'unsafe-inline';")
        end
      end
    end
  end
end
