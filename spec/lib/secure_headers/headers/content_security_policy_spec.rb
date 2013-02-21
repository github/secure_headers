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
        :style_src => "inline https://* about:"
      }
    end

    IE = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    FIREFOX = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.2) Gecko/20121223 Ubuntu/9.25 (jaunty) Firefox/3.8"
    FIREFOX_18 = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:18.0) Gecko/18.0 Firefox/18.0"
    CHROME = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"

    def request_for user_agent, request_uri=nil, options={:ssl => false}
      double(:ssl? => options[:ssl], :env => {'HTTP_USER_AGENT' => user_agent}, :url => (request_uri || 'http://areallylongdomainexample.com') )
    end

    before(:each) do
      @options_with_forwarding = default_opts.merge(:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com')
    end

    describe "#name" do
      context "when supplying options to override request" do
        specify { ContentSecurityPolicy.new(default_opts, :ua => IE).name.should == STANDARD_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(default_opts, :ua => FIREFOX).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(default_opts, :ua => CHROME).name.should == WEBKIT_CSP_HEADER_NAME + "-Report-Only"}
      end

      context "when in report-only mode" do
        specify { ContentSecurityPolicy.new(default_opts, :request => request_for(IE)).name.should == STANDARD_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX)).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME)).name.should == WEBKIT_CSP_HEADER_NAME + "-Report-Only"}
      end

      context "when in enforce mode" do
        let(:opts) { default_opts.merge(:enforce => true)}

        specify { ContentSecurityPolicy.new(opts, :request => request_for(IE)).name.should == STANDARD_HEADER_NAME}
        specify { ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX)).name.should == FIREFOX_CSP_HEADER_NAME}
        specify { ContentSecurityPolicy.new(opts, :request => request_for(CHROME)).name.should == WEBKIT_CSP_HEADER_NAME}
      end

      context "when in experimental mode" do
        let(:opts) { default_opts.merge(:enforce => true).merge(:experimental => {})}
        specify { ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(IE)}).name.should == STANDARD_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(FIREFOX)}).name.should == FIREFOX_CSP_HEADER_NAME + "-Report-Only"}
        specify { ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(CHROME)}).name.should == WEBKIT_CSP_HEADER_NAME + "-Report-Only"}
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
          csp = ContentSecurityPolicy.new(@opts, :request => request_for(FIREFOX))
          csp.value.should include("script-src https://* data: 'self' 'none'")
          csp.value.should include('options inline-script eval-script')
        end
      end

      context "X-Webkit-CSP" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(@opts, :request => request_for(CHROME))
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
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX))
          browser_specific = csp.send :build_impl_specific_directives
          browser_specific.should include('options inline-script eval-script;')
        end

        it "does not move values from style-src into options" do
          opts = {
            :default_src => 'https://*',
            :style_src => "inline eval https://*"
          }
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX))
          browser_specific = csp.send :build_impl_specific_directives
          browser_specific.should_not include('inline-script')
          browser_specific.should_not include('eval-script')
        end
      end
    end

    describe "#same_origin?" do
      let(:origin) {"https://example.com:123"}

      it "matches when host, scheme, and port match" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://example.com"))
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://example.com:443"))
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com:123'}, :request => request_for(FIREFOX, "https://example.com:123"))
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com"))
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com:80'}, :request => request_for(FIREFOX, "http://example.com"))
        csp.send(:same_origin?).should be_true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com:80"))
        csp.send(:same_origin?).should be_true
      end

      it "does not match port mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com:81"))
        csp.send(:same_origin?).should be_false
      end

      it "does not match host mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://twitter.com'}, :request => request_for(FIREFOX, "http://example.com"))
        csp.send(:same_origin?).should be_false
      end

      it "does not match host mismatches because of subdomains" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://sub.example.com"))
        csp.send(:same_origin?).should be_false
      end

      it "does not match scheme mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "ftp://example.com"))
        csp.send(:same_origin?).should be_false
      end

      it "does not match on substring collisions" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://anotherexample.com"))
        csp.send(:same_origin?).should be_false
      end


    end

    describe "#normalize_reporting_endpoint" do
      let(:opts) {{:report_uri => 'https://example.com/csp', :forward_endpoint => anything}}

      context "when using firefox" do
        it "updates the report-uri when posting to a different host" do
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX, "https://anexample.com"))
          csp.report_uri.should == FF_CSP_ENDPOINT
        end

        context "when the report-uri is a path" do
          it "doesn't change report-uri" do
            csp = ContentSecurityPolicy.new({:report_uri => "/csp_reports"}, :request => request_for(FIREFOX, "https://anexample.com"))
            csp.report_uri.should == "/csp_reports"
          end

          it "changes the report-uri if the forward_endpoint is supplied" do
            csp = ContentSecurityPolicy.new({:report_uri => "/csp_reports", :forward_endpoint => 'http://example.com/csp'}, :request => request_for(FIREFOX, "https://anexample.com"))
            csp.report_uri.should == FF_CSP_ENDPOINT
          end
        end

        it "forwards if the request_uri is set to a non-matching value" do
          csp = ContentSecurityPolicy.new({:report_uri => "https://another.example.com", :forward_endpoint => '/somewhere'}, :ua => "Firefox", :request_uri => "https://anexample.com")
          csp.report_uri.should == FF_CSP_ENDPOINT
        end
      end

      it "does not update the URI is the report_uri is on the same origin" do
        opts = {:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com'}
        csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX, "https://example.com/somewhere"))
        csp.report_uri.should == 'https://example.com/csp'
      end

      it "does not update the report-uri when using a non-firefox browser" do
        csp = ContentSecurityPolicy.new(opts, :request => request_for(CHROME))
        csp.report_uri.should == 'https://example.com/csp'
      end
    end

    describe "#value" do
      it "raises an exception when default-src is missing" do
        csp = ContentSecurityPolicy.new({:script_src => 'anything'}, :request => request_for(CHROME))
        lambda {
          csp.value
        }.should raise_error(ContentSecurityPolicyBuildError, "Couldn't build CSP header :( Expected to find default_src directive value")
      end

      context "auto-whitelists data: uris for img-src" do

        it "sets the value if no img-src specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true}, :request => request_for(CHROME))
          csp.value.should == "default-src 'self'; img-src data:;"
        end

        it "appends the value if img-src is specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :img_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true}, :request => request_for(CHROME))
          csp.value.should == "default-src 'self'; img-src 'self' data:;"
        end
      end

      it "fills in directives without values with default-src value" do
        options = default_opts.merge(:disable_fill_missing => false)
        csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
        value = "default-src https://*; connect-src https://*; font-src https://*; frame-src https://*; img-src https://* data:; media-src https://*; object-src https://*; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;"
        csp.value.should == value
      end

      it "sends the chrome csp header if an unknown browser is supplied" do
        csp = ContentSecurityPolicy.new(default_opts, :request => request_for(IE))
        csp.value.should match "default-src"
      end

      context "X-Content-Security-Policy" do
        it "builds a csp header for firefox" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX))
          csp.value.should == "allow https://*; options inline-script eval-script; img-src data:; script-src https://* data:; style-src https://* about:; report-uri /csp_report;"
        end

        it "does not append chrome-extension to directives" do
          csp = ContentSecurityPolicy.new(default_opts.merge(:disable_chrome_extension => false), :request => request_for(FIREFOX))
          csp.value.should_not match "chrome-extension:"
        end

        it "copies connect-src values to xhr_src values" do
          opts = {
            :default_src => 'http://twitter.com',
            :connect_src => 'self http://*.localhost.com:*',
            :disable_chrome_extension => true,
            :disable_fill_missing => true
          }
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX))
          csp.value.should =~ /xhr-src 'self' http:/
        end

        it "copies connect-src values to xhr_src values for FF 18" do
          opts = {
            :default_src => 'http://twitter.com',
            :connect_src => 'self http://*.localhost.com:*',
            :disable_chrome_extension => true,
            :disable_fill_missing => true
          }
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX_18))
          csp.value.should =~ /xhr-src 'self' http:\/\/\*\.localhost\.com:\*/
        end
      end

      context "X-Webkit-CSP" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME))
          csp.value.should == "default-src https://*; img-src data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;"
        end

        it "ignores :forward_endpoint settings" do
          csp = ContentSecurityPolicy.new(@options_with_forwarding, :request => request_for(CHROME))
          csp.value.should =~ /report-uri #{@options_with_forwarding[:report_uri]};/
        end

        it "whitelists chrome_extensions by default" do
          opts = {
            :default_src => 'https://*',
            :report_uri => '/csp_report',
            :script_src => 'inline eval https://* data:',
            :style_src => "inline https://* chrome-extension: about:"
          }

          csp = ContentSecurityPolicy.new(opts, :request => request_for(CHROME))

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
          header = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
          header.value.should == "default-src 'self'; img-src data:; script-src https://*;"
        end

        it "it returns the experimental value if requested" do
          header = ContentSecurityPolicy.new(options, {:request => request_for(CHROME), :experimental => true})
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
          csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
          csp.value.should == "default-src https://*; frame-src http://*; img-src http://* data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;"
        end

        it "does not add the directive values if requesting https" do
          csp = ContentSecurityPolicy.new(options, :request => request_for(CHROME, '/', :ssl => true))
          csp.value.should_not =~ /http:/
        end

        it "does not add the directive values if requesting https" do
          csp = ContentSecurityPolicy.new(options, :ua => "Chrome", :ssl => true)
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
            csp = ContentSecurityPolicy.new(options, :experimental => true, :request => request_for(FIREFOX, '/', :ssl => true))
            csp.value.should == "allow 'self'; img-src data:; script-src 'self';"
          end

          it "detects the :ssl => true option" do
            csp = ContentSecurityPolicy.new(options, :experimental => true, :ua => FIREFOX, :ssl => true)
            csp.value.should == "allow 'self'; img-src data:; script-src 'self';"
          end

          it "merges the values from experimental/http_additions when not over SSL" do
            csp = ContentSecurityPolicy.new(options, :experimental => true, :request => request_for(FIREFOX))
            csp.value.should == "allow 'self'; img-src data:; script-src 'self' https://mycdn.example.com;"
          end
        end
      end
    end
  end
end
