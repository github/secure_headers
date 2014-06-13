require 'spec_helper'

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
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => IE).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => FIREFOX).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => FIREFOX_23).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => CHROME).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :ua => CHROME_25).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
      end

      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(IE)).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX)).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(FIREFOX_23)).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME)).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME_25)).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
      end

      context "when in enforce mode" do
        let(:opts) { default_opts.merge(:enforce => true)}

        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(IE)).name).to eq(STANDARD_HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX)).name).to eq(STANDARD_HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX_23)).name).to eq(STANDARD_HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(CHROME)).name).to eq(STANDARD_HEADER_NAME)}
        specify { expect(ContentSecurityPolicy.new(opts, :request => request_for(CHROME_25)).name).to eq(STANDARD_HEADER_NAME)}
      end

      context "when in experimental mode" do
        let(:opts) { default_opts.merge(:enforce => true).merge(:experimental => {})}
        specify { expect(ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(IE)}).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(FIREFOX)}).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(FIREFOX_23)}).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(CHROME)}).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
        specify { expect(ContentSecurityPolicy.new(opts, {:experimental => true, :request => request_for(CHROME_25)}).name).to eq(STANDARD_HEADER_NAME + "-Report-Only")}
      end
    end

    describe "#normalize_csp_options" do
      before(:each) do
        default_opts.delete(:disable_chrome_extension)
        default_opts.delete(:disable_fill_missing)
        default_opts[:script_src] << ' self none'
        @opts = default_opts
      end

      context "Content-Security-Policy" do
        it "converts the script values to their equivilents" do
          csp = ContentSecurityPolicy.new(@opts, :request => request_for(CHROME))
          expect(csp.value).to include("script-src 'unsafe-inline' 'unsafe-eval' https://* data: 'self' 'none'")
        end

        it "accepts procs for report-uris" do
          opts = {
            :default_src => 'self',
            :report_uri => lambda { "http://lambda/result" }
          }

          csp = ContentSecurityPolicy.new(opts)
          expect(csp.report_uri).to eq("http://lambda/result")
        end

        it "accepts procs for other fields" do
          opts = {
            :default_src => lambda { "http://lambda/result" }
          }

          csp = ContentSecurityPolicy.new(opts).value
          expect(csp).to match("default-src http://lambda/result")
        end
      end
    end

    describe "#same_origin?" do
      let(:origin) {"https://example.com:123"}

      it "matches when host, scheme, and port match" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://example.com"))
        expect(csp.send(:same_origin?)).to be true

        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://example.com:443"))
        expect(csp.send(:same_origin?)).to be true

        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com:123'}, :request => request_for(FIREFOX, "https://example.com:123"))
        expect(csp.send(:same_origin?)).to be true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com"))
        expect(csp.send(:same_origin?)).to be true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com:80'}, :request => request_for(FIREFOX, "http://example.com"))
        expect(csp.send(:same_origin?)).to be true

        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com:80"))
        expect(csp.send(:same_origin?)).to be true
      end

      it "does not match port mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://example.com:81"))
        expect(csp.send(:same_origin?)).to be false
      end

      it "does not match host mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://twitter.com'}, :request => request_for(FIREFOX, "http://example.com"))
        expect(csp.send(:same_origin?)).to be false
      end

      it "does not match host mismatches because of subdomains" do
        csp = ContentSecurityPolicy.new({:report_uri => 'http://example.com'}, :request => request_for(FIREFOX, "http://sub.example.com"))
        expect(csp.send(:same_origin?)).to be false
      end

      it "does not match scheme mismatches" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "ftp://example.com"))
        expect(csp.send(:same_origin?)).to be false
      end

      it "does not match on substring collisions" do
        csp = ContentSecurityPolicy.new({:report_uri => 'https://example.com'}, :request => request_for(FIREFOX, "https://anotherexample.com"))
        expect(csp.send(:same_origin?)).to be false
      end
    end

    describe "#normalize_reporting_endpoint" do
      let(:opts) {{:report_uri => 'https://example.com/csp', :forward_endpoint => anything}}

      context "when using firefox" do
        it "updates the report-uri when posting to a different host" do
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX, "https://anexample.com"))
          expect(csp.report_uri).to eq(FF_CSP_ENDPOINT)
        end

        it "doesn't change report-uri if a path supplied" do
          csp = ContentSecurityPolicy.new({:report_uri => "/csp_reports"}, :request => request_for(FIREFOX, "https://anexample.com"))
          expect(csp.report_uri).to eq("/csp_reports")
        end

        it "forwards if the request_uri is set to a non-matching value" do
          csp = ContentSecurityPolicy.new({:report_uri => "https://another.example.com", :forward_endpoint => '/somewhere'}, :ua => "Firefox", :request_uri => "https://anexample.com")
          expect(csp.report_uri).to eq(FF_CSP_ENDPOINT)
        end
      end

      it "does not update the URI is the report_uri is on the same origin" do
        opts = {:report_uri => 'https://example.com/csp', :forward_endpoint => 'https://anotherexample.com'}
        csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX, "https://example.com/somewhere"))
        expect(csp.report_uri).to eq('https://example.com/csp')
      end

      it "does not update the report-uri when using a non-firefox browser" do
        csp = ContentSecurityPolicy.new(opts, :request => request_for(CHROME))
        expect(csp.report_uri).to eq('https://example.com/csp')
      end

      context "when using a protocol-relative value for report-uri" do
        let(:opts) {
          {
            :default_src => 'self',
            :report_uri => '//example.com/csp'
          }
        }

        it "uses the current protocol" do
          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX, '/', :ssl => true))
          expect(csp.value).to match(%r{report-uri https://example.com/csp;})

          csp = ContentSecurityPolicy.new(opts, :request => request_for(FIREFOX))
          expect(csp.value).to match(%r{report-uri http://example.com/csp;})
        end

        it "uses the pre-configured https protocol" do
          csp = ContentSecurityPolicy.new(opts, :ua => "Firefox", :ssl => true)
          expect(csp.value).to match(%r{report-uri https://example.com/csp;})
        end

        it "uses the pre-configured http protocol" do
          csp = ContentSecurityPolicy.new(opts, :ua => "Firefox", :ssl => false)
          expect(csp.value).to match(%r{report-uri http://example.com/csp;})
        end
      end
    end

    describe "#value" do
      it "raises an exception when default-src is missing" do
        csp = ContentSecurityPolicy.new({:script_src => 'anything'}, :request => request_for(CHROME))
        expect {
          csp.value
        }.to raise_error(ContentSecurityPolicyBuildError, "Couldn't build CSP header :( Expected to find default_src directive value")
      end

      context "auto-whitelists data: uris for img-src" do
        it "sets the value if no img-src specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true}, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src 'self'; img-src data:;")
        end

        it "appends the value if img-src is specified" do
          csp = ContentSecurityPolicy.new({:default_src => 'self', :img_src => 'self', :disable_fill_missing => true, :disable_chrome_extension => true}, :request => request_for(CHROME))
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
          expect(csp.value).to eq("default-src https://*; img-src data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;")
        end
      end

      context "Chrome" do
        it "builds a csp header for chrome" do
          csp = ContentSecurityPolicy.new(default_opts, :request => request_for(CHROME))
          expect(csp.value).to eq("default-src https://*; img-src data:; script-src 'unsafe-inline' 'unsafe-eval' https://* data:; style-src 'unsafe-inline' https://* about:; report-uri /csp_report;")
        end

        it "ignores :forward_endpoint settings" do
          csp = ContentSecurityPolicy.new(@options_with_forwarding, :request => request_for(CHROME))
          expect(csp.value).to match(/report-uri #{@options_with_forwarding[:report_uri]};/)
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

        it "returns the original value" do
          header = ContentSecurityPolicy.new(options, :request => request_for(CHROME))
          expect(header.value).to eq("default-src 'self'; img-src data:; script-src https://*;")
        end

        it "it returns the experimental value if requested" do
          header = ContentSecurityPolicy.new(options, {:request => request_for(CHROME), :experimental => true})
          expect(header.value).not_to match(/https/)
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
          # "allow 'self'; script-src https://* http://*" for http requests

          it "uses the value in the experimental block over SSL" do
            csp = ContentSecurityPolicy.new(options, :experimental => true, :request => request_for(FIREFOX, '/', :ssl => true))
            expect(csp.value).to eq("default-src 'self'; img-src data:; script-src 'self';")
          end

          it "detects the :ssl => true option" do
            csp = ContentSecurityPolicy.new(options, :experimental => true, :ua => FIREFOX, :ssl => true)
            expect(csp.value).to eq("default-src 'self'; img-src data:; script-src 'self';")
          end

          it "merges the values from experimental/http_additions when not over SSL" do
            csp = ContentSecurityPolicy.new(options, :experimental => true, :request => request_for(FIREFOX))
            expect(csp.value).to eq("default-src 'self'; img-src data:; script-src 'self' https://mycdn.example.com;")
          end
        end
      end
    end
  end
end
