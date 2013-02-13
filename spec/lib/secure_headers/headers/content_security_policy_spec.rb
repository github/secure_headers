require 'spec_helper'
require 'brwsr'

module SecureHeaders
  describe ContentSecurityPolicy do
    let(:default_opts) do
      {
        :disable_chrome_extension => true,
        :disable_fill_missing => true,
        :default_src => 'https://*',
        :report_uri => '/csp_report',
        :script_src => 'inline eval https://* data:',
        :style_src => "inline https://* chrome-extension: about:"
      }
    end

    IE = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    FIREFOX = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.2) Gecko/20121223 Ubuntu/9.25 (jaunty) Firefox/3.8"
    FIREFOX_18 = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:18.0) Gecko/18.0 Firefox/18.0"
    CHROME = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"

    def request_for user_agent, request_uri=nil, options={:ssl => false}
      double(:ssl? => options[:ssl], :env => {'HTTP_USER_AGENT' => user_agent}, :url => (request_uri || 'http://example.com') )
    end

    before(:each) do
      @options_with_forwarding = default_opts.merge(:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com')
    end

    describe "#name" do
      context "when in report-only mode" do
        specify { ContentSecurityPolicy.new(request_for(IE), default_opts).name.should == STANDARD_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX), default_opts).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX_18), default_opts).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(CHROME), default_opts).name.should == WEBKIT_CSP_HEADER_NAME + "-Report-Only"}
      end

      context "when in enforce mode" do
        let(:opts) { default_opts.merge(:enforce => true)}

        specify { ContentSecurityPolicy.new(request_for(IE), opts).name.should == STANDARD_HEADER_NAME}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX), opts).name.should == FIREFOX_CSP_HEADER_NAME}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX_18), opts).name.should == FIREFOX_CSP_HEADER_NAME}
        specify { ContentSecurityPolicy.new(request_for(CHROME), opts).name.should == WEBKIT_CSP_HEADER_NAME}
      end

      context "when in experimental mode" do
        let(:opts) { default_opts.merge(:enforce => true).merge(:experimental => {})}
        specify { ContentSecurityPolicy.new(request_for(IE), opts, :experimental => true).name.should == STANDARD_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX), opts, :experimental => true).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(FIREFOX_18), opts, :experimental => true).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(request_for(CHROME), opts, :experimental => true).name.should == WEBKIT_CSP_HEADER_NAME + "-Report-Only"}
      end
    end

    describe "#fill_directives" do
      let(:opts) {{:default_src => ['https://*']}}
      let(:expected) {{}}

      it "fills empty directives with the 'allow' directive in Firefox" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX), opts)
        csp.directives.each {|dir| expected[dir] = ["https://*"]}
        csp.send(:fill_directives).should == expected.merge(opts)
      end

      it "fills empty directives with the 'default' directive in Chrome" do
        csp = ContentSecurityPolicy.new(request_for(CHROME), opts)
        csp.directives.each {|dir| expected[dir] = ["https://*"]}
        csp.send(:fill_directives).should == expected.merge(opts)
      end

      it "does not overwrite supplied values" do
        options = opts.merge(:img_src => ['https://twitter.com'])
        csp = ContentSecurityPolicy.new(request_for(CHROME), options)
        csp.directives.each {|dir| expected[dir] = ["https://*"]}
        csp.send(:fill_directives).should == expected.merge(options)
      end
    end

    describe "#normalize_csp_options" do
      before(:each) do
        default_opts.delete(:disable_chrome_extension)
        default_opts.delete(:disable_fill_missing)
        default_opts[:script_src] << ' self none'
        @opts = default_opts
      end

      context "X-Content-Security-Policy" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(request_for(FIREFOX), @opts)
          csp.value.should include("script-src https://* data: 'self' 'none'")
          csp.value.should include('options inline-script eval-script')
        end
      end

      context "X-Webkit-CSP" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(request_for(CHROME), @opts)
          csp.value.should include("script-src 'unsafe-inline' 'unsafe-eval' https://* data: 'self' 'none' chrome-extension")
        end
      end
    end

    describe "#build_impl_specific_directives" do
      context "X-Content-Security-Policy" do
        it "moves script-src inline and eval values to the options directive" do
          opts = {
            :default_src => 'https://*',
            :script_src => "inline eval https://*"
          }
          csp = ContentSecurityPolicy.new(request_for(FIREFOX), opts)
          browser_specific = csp.send :build_impl_specific_directives
          browser_specific.should include('options inline-script eval-script;')
        end

        it "does not move values from style-src into options" do
          opts = {
            :default_src => 'https://*',
            :style_src => "inline eval https://*"
          }
          csp = ContentSecurityPolicy.new(request_for(FIREFOX), opts)
          browser_specific = csp.send :build_impl_specific_directives
          browser_specific.should_not include('inline-script')
          browser_specific.should_not include('eval-script')
        end
      end
    end

    describe "#supports_standard?" do
      ['IE', 'Safari', 'Chrome'].each do |browser_name|
        it "returns true for #{browser_name}" do
          browser = Brwsr::Browser.new(:ua => browser_name)
          subject.stub(:browser).and_return(browser)
          subject.send(:supports_standard?).should be_true
        end
      end

      it "returns true for Firefox v >= 18" do
        browser = Brwsr::Browser.new(:ua => "Firefox 18")
        subject.stub(:browser).and_return(browser)
        subject.send(:supports_standard?).should be_true
      end

      it "returns false for Firefox v < 18" do
        browser = Brwsr::Browser.new(:ua => "Firefox 17")
        subject.stub(:browser).and_return(browser)
        subject.send(:supports_standard?).should be_false
      end
    end

    describe "#same_origin?" do
      let(:origin) {"https://example.com:123"}

      it "matches when host, scheme, and port match" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "https://example.com"), {:report_uri => 'https://example.com'})
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "https://example.com:443"), {:report_uri => 'https://example.com'})
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "https://example.com:123"), {:report_uri => 'https://example.com:123'})
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://example.com"), {:report_uri => 'http://example.com'})
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://example.com"), {:report_uri => 'http://example.com:80'})
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://example.com:80"), {:report_uri => 'http://example.com'})
        csp.send(:same_origin?).should be_true
      end

      it "does not match port mismatches" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://example.com:81"), {:report_uri => 'http://example.com'})
        csp.send(:same_origin?).should be_false
      end

      it "does not match host mismatches" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://example.com"), {:report_uri => 'http://twitter.com'})
        csp.send(:same_origin?).should be_false
      end

      it "does not match host mismatches because of subdomains" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "http://sub.example.com"), {:report_uri => 'http://example.com'})
        csp.send(:same_origin?).should be_false
      end

      it "does not match scheme mismatches" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "ftp://example.com"), {:report_uri => 'https://example.com'})
        csp.send(:same_origin?).should be_false
      end

      it "does not match on substring collisions" do
        csp = ContentSecurityPolicy.new(request_for(FIREFOX, "https://anotherexample.com"), {:report_uri => 'https://example.com'})
        csp.send(:same_origin?).should be_false
      end
    end

    describe "#normalize_reporting_endpoint" do
      let(:opts) {{:report_uri => 'https://example.com/csp', :forward_endpoint => anything}}

      context "when using firefox" do
        it "updates the report-uri when posting to a different host" do
          subject.configure(request_for(FIREFOX, "https://anexample.com"), opts)
          subject.report_uri.should == FF_CSP_ENDPOINT
        end

        it "updates the report-uri when posting to a different host for Firefox >= 18" do
          subject.configure(request_for(FIREFOX, "https://anexample.com"), opts)
          subject.report_uri.should == FF_CSP_ENDPOINT
        end

        it "does not update the URI is the report_uri is on the same origin" do
          opts = {:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com'}
          subject.configure(request_for(FIREFOX, "https://example.com/somewhere"), opts)
          subject.report_uri.should == 'https://example.com/csp'
        end

        it "does not update the report-uri when using a non-firefox browser" do
          subject.configure(request_for(CHROME), opts)
          subject.report_uri.should == 'https://example.com/csp'
        end
      end
    end

    describe "#value" do
      it "raises an exception when default-src is missing" do
        subject.configure(request_for(CHROME), {:script_src => 'anything'})
        lambda {
          subject.value
        }.should raise_error(ContentSecurityPolicyBuildError, "Couldn't build CSP header :( Expected to find default_src directive value")
      end

      context "auto-whitelists data: uris for img-src" do

        it "sets the value if no img-src specified" do
          csp = ContentSecurityPolicy.new(request_for(CHROME), {:default_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true})
          csp.value.should == "default-src 'self'; img-src data:;"
        end

        it "appends the value if img-src is specified" do
          csp = ContentSecurityPolicy.new(request_for(CHROME), {:default_src => 'self', :img_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true})
          csp.value.should == "default-src 'self'; img-src 'self' data:;"
        end
      end

      it "fills in directives without values with default-src value" do
        options = default_opts.merge(:disable_fill_missing => false)
        csp = ContentSecurityPolicy.new(request_for(CHROME), options)
        value = "default-src https://*; connect-src https://*; font-src https://*; frame-src https://*; img-src https://* data:; media-src https://*; object-src https://*; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* chrome-extension: about:; report-uri /csp_report;"
        csp.value.should == value
      end

      it "sends the chrome csp header if an unknown browser is supplied" do
        csp = ContentSecurityPolicy.new(request_for(IE), default_opts)
        csp.value.should match "default-src"
      end

      context "X-Content-Security-Policy" do
        it "builds a csp header for firefox" do
          csp = ContentSecurityPolicy.new(request_for(FIREFOX), default_opts)
          csp.value.should == "allow https://*; options inline-script eval-script; img-src data:; script-src https://* data:; style-src https://* chrome-extension: about:; report-uri /csp_report;"
        end

        it "copies connect-src values to xhr_src values" do
          opts = {
            :default_src => 'http://twitter.com',
            :connect_src => 'self http://*.localhost.com:*',
            :disable_chrome_extension => true,
            :disable_fill_missing => true
          }
          csp = ContentSecurityPolicy.new(request_for(FIREFOX), opts)
          csp.value.should =~ /xhr-src 'self' http:/
        end

        it "copies connect-src values to xhr_src values for FF 18" do
          opts = {
            :default_src => 'http://twitter.com',
            :connect_src => 'self http://*.localhost.com:*',
            :disable_chrome_extension => true,
            :disable_fill_missing => true
          }
          csp = ContentSecurityPolicy.new(request_for(FIREFOX_18), opts)
          csp.value.should =~ /xhr-src 'self' http:\/\/\*\.localhost\.com:\*/
        end

        it "builds a w3c-style-ish header for Firefox > version 18" do
          csp = ContentSecurityPolicy.new(request_for(FIREFOX_18), default_opts)
          csp.value.should =~ /default-src/
        end
      end

      context "X-Webkit-CSP" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(request_for(CHROME), default_opts)
          csp.value.should == "default-src https://*; img-src data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* chrome-extension: about:; report-uri /csp_report;"
        end

        it "ignores :forward_endpoint settings" do
          csp = ContentSecurityPolicy.new(request_for(CHROME), @options_with_forwarding)
          csp.value.should =~ /report-uri #{@options_with_forwarding[:report_uri]};/
        end

        it "whitelists chrome_extensions by default" do
          opts = {
            :default_src => 'https://*',
            :report_uri => '/csp_report',
            :script_src => 'inline eval https://* data:',
            :style_src => "inline https://* chrome-extension: about:"
          }

          csp = ContentSecurityPolicy.new(request_for(CHROME), opts)

          # ignore the report-uri directive
          csp.value.split(';')[0...-1].each{|directive| directive.should =~ /chrome-extension:/}
        end
      end

      context "when supplying a experimental values" do
        let(:options) {{
          :disable_chrome_extension => true,
          :disable_fill_missing => true,
          :default_src => 'self',
          :script_src => 'https://*',
          :experimental => {
            :script_src => 'self'
          }
        }}

        let(:header) {}
        it "returns the original value" do
          header = ContentSecurityPolicy.new(request_for(CHROME), options)
          header.value.should == "default-src 'self'; img-src data:; script-src https://*;"
        end

        it "it returns the experimental value if requested" do
          header = ContentSecurityPolicy.new(request_for(CHROME), options, :experimental => true)
          header.value.should_not =~ /https/
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
          csp = ContentSecurityPolicy.new(request_for(CHROME), options)
          csp.value.should == "default-src https://*; frame-src http://*; img-src http://* data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* chrome-extension: about:; report-uri /csp_report;"
        end

        it "does not add the directive values if requesting https" do
          csp = ContentSecurityPolicy.new(request_for(CHROME, '/', :ssl => true), options)
          csp.value.should_not =~ /http:/
        end

        context "when supplying an experimental block" do
          # this simulates the situation where we are enforcing that scripts
          # only come from http[s]? depending if we're on ssl or not. The
          # report only tag will allow scripts from self over ssl, and
          # from a secure CDN over non-ssl
          let(:options) {{
            :disable_chrome_extension => true,
            :disable_fill_missing => true,
            :default_src => 'self',
            :script_src => 'https://*',
            :http_additions => {
              :script_src => 'http://*'
            },
            :experimental => {
              :script_src => 'self',
              :http_additions => {
                :script_src => 'https://mycdn.example.com'
              }
            }
          }}
          # for comparison purposes, if not using the experimental header this would produce
          # "allow 'self'; script-src https://*" for https requests
          # and
          # "allow 'self; script-src https://* http://*" for http requests

          it "uses the value in the experimental block over SSL" do
            csp = ContentSecurityPolicy.new(request_for(FIREFOX, '/', :ssl => true), options, :experimental => true)
            csp.value.should == "allow 'self'; img-src data:; script-src 'self';"
          end

          it "merges the values from experimental/http_additions when not over SSL" do
            csp = ContentSecurityPolicy.new(request_for(FIREFOX), options, :experimental => true)
            csp.value.should == "allow 'self'; img-src data:; script-src 'self' https://mycdn.example.com;"
          end
        end
      end
    end
  end
end
