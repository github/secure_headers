require 'spec_helper'

module SecureHeaders
  describe ContentSecurityPolicy do
    let (:default_opts) do
      {
        default_src: %w(https:),
        img_src: %w(https: data:),
        script_src: %w('unsafe-inline' 'unsafe-eval' https: data:),
        style_src: %w('unsafe-inline' https: about:),
        report_uri: %w(/csp_report)
      }
    end

    describe "#name" do
      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(report_only: true)).name).to eq(ContentSecurityPolicy::HEADER_NAME + "-Report-Only") }
      end

      context "when in enforce mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts).name).to eq(ContentSecurityPolicy::HEADER_NAME) }
      end
    end

    describe "#value" do
      it "discards 'none' values if any other source expressions are present" do
        csp = ContentSecurityPolicy.new(default_opts.merge(frame_src: %w('self' 'none')))
        expect(csp.value).not_to include("'none'")
      end

      it "discards source expressions (besides unsafe-* and non-host source values) when * is present" do
        csp = ContentSecurityPolicy.new(default_src: %w(* 'unsafe-inline' 'unsafe-eval' http: https: example.org data: blob:))
        expect(csp.value).to eq("default-src * 'unsafe-inline' 'unsafe-eval' data: blob:")
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

      it "does not remove schemes from report-uri values" do
        csp = ContentSecurityPolicy.new(default_src: %w(https:), report_uri: %w(https://example.org))
        expect(csp.value).to eq("default-src https:; report-uri https://example.org")
      end

      it "does not remove schemes when :preserve_schemes is true" do
        csp = ContentSecurityPolicy.new(default_src: %w(https://example.org), :preserve_schemes => true)
        expect(csp.value).to eq("default-src https://example.org")
      end

      it "removes nil from source lists" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org", nil])
        expect(csp.value).to eq("default-src example.org")
      end

      it "does not add a directive if the value is an empty array (or all nil)" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org"], script_src: [nil])
        expect(csp.value).to eq("default-src example.org")
      end

      it "does not add a directive if the value is nil" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org"], script_src: nil)
        expect(csp.value).to eq("default-src example.org")
      end

      it "deduplicates any source expressions" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org example.org example.org))
        expect(csp.value).to eq("default-src example.org")
      end

      context "browser sniffing" do
        let (:complex_opts) do
          ContentSecurityPolicy::ALL_DIRECTIVES.each_with_object({}) do |directive, hash|
            hash[directive] = %w('self')
          end.merge({
            block_all_mixed_content: true,
            upgrade_insecure_requests: true,
            reflected_xss: "block",
            script_src: %w('self'),
            script_nonce: 123456
          })
        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:chrome])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; upgrade-insecure-requests; report-uri 'self'")
        end

        it "does not filter any directives for Opera" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:opera])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; upgrade-insecure-requests; report-uri 'self'")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; upgrade-insecure-requests; report-uri 'self'")
        end

        it "adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for Edge" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:edge])
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; report-uri 'self'")
        end

        it "adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari6])
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; report-uri 'self'")
        end
      end
    end
  end
end
