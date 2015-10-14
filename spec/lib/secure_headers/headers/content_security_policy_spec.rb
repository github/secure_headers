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

    IE = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
    FIREFOX = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.2) Gecko/20121223 Ubuntu/9.25 (jaunty) Firefox/3.8"
    FIREFOX_23 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0"
    CHROME = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"
    CHROME_25 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"
    SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
    OPERA = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16"

    describe "#name" do
      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts).name).to eq(ContentSecurityPolicy::HEADER_NAME + "-Report-Only")}
      end

      context "when in enforce mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(:enforce => true)).name).to eq(ContentSecurityPolicy::HEADER_NAME) }
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

    describe "#validate_config!" do
      it "requires a :default_src value" do
        expect {
          CSP.validate_config!(script_src: %('self'))
        }.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :enforce to be a truthy value" do
        expect {
          CSP.validate_config!(default_opts.merge(enforce: "steve"))
        }.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :block_all_mixed_content to be a boolean value" do
        expect {
          CSP.validate_config!(default_opts.merge(block_all_mixed_content: "steve"))
        }.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires all source lists to be an array of strings" do
        expect {
          CSP.validate_config!(default_src: "steve")
        }.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "rejects unknown directives / config" do
        expect {
          CSP.validate_config!(default_src: %w('self'), default_src_totally_mispelled: "steve")
        }.to raise_error(ContentSecurityPolicyConfigError)
      end

      # this is mostly to ensure people don't use the antiquated shorthands common in other configs
      it "performs light validation on source lists" do
        expect {
          CSP.validate_config!(default_src: %w(self none inline eval))
        }.to raise_error(ContentSecurityPolicyConfigError)
      end
    end

    describe "#value" do
      it "discards 'none' values if any other source expressions are present" do
        csp = ContentSecurityPolicy.new(default_opts.merge(:frame_src => %w('self' 'none')))
        expect(csp.value).not_to include("'none'")
      end

      it "discards any other source expressions when * is present" do
        csp = ContentSecurityPolicy.new(default_src: %w(* http: https: example.org))
        expect(csp.value).to eq("default-src *")
      end

      it "minifies source expressions based on overlapping wildcards" do
        config = {
          default_src: %w(a.example.org b.example.org *.example.org https://*.example.org)
        }
        csp = ContentSecurityPolicy.new(config)
        expect(csp.value).to eq("default-src *.example.org")
      end

      it "removes http/s schemes from hosts" do
        csp = ContentSecurityPolicy.new(default_src: %w(https://example.org))
        expect(csp.value).to eq("default-src example.org")
      end

      it "removes nil from source lists" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org", nil])
        expect(csp.value).to eq("default-src example.org")
      end

      it "deduplicates any source expressions" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org example.org example.org))
        expect(csp.value).to eq("default-src example.org")
      end

      context "browser sniffing" do
        let(:complex_opts) do
          ContentSecurityPolicy::ALL_DIRECTIVES.inject({}) { |memo, directive| memo[directive] = %w('self'); memo }.
          merge(:block_all_mixed_content => true, :reflected_xss => "block").
          merge(:script_src => %w('self' 'nonce-123456' 'sha256-abc123'))

        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: CHROME))
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456' 'sha256-abc123'; style-src 'self'; report-uri 'self'")
        end

        it "does not filter any directives for Opera" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: OPERA))
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456' 'sha256-abc123'; style-src 'self'; report-uri 'self'")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types, and hash sources for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: FIREFOX))
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'nonce-123456' 'sha256-abc123'; style-src 'self'; report-uri 'self'")
        end

        it "filters base-uri, blocked-all-mixed-content, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts.merge(ua: SAFARI))
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self'; style-src 'self'; report-uri 'self'")
        end
      end
    end
  end
end
