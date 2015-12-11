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
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(:report_only => true)).name).to eq(ContentSecurityPolicy::HEADER_NAME + "-Report-Only") }
      end

      context "when in enforce mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts).name).to eq(ContentSecurityPolicy::HEADER_NAME) }
      end
    end

    describe "#validate_config!" do
      it "requires a :default_src value" do
        expect do
          CSP.validate_config!(script_src: %('self'))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :report_only to be a truthy value" do
        expect do
          CSP.validate_config!(default_opts.merge(report_only: "steve"))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :block_all_mixed_content to be a boolean value" do
        expect do
          CSP.validate_config!(default_opts.merge(block_all_mixed_content: "steve"))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires all source lists to be an array of strings" do
        expect do
          CSP.validate_config!(default_src: "steve")
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "rejects unknown directives / config" do
        expect do
          CSP.validate_config!(default_src: %w('self'), default_src_totally_mispelled: "steve")
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      # this is mostly to ensure people don't use the antiquated shorthands common in other configs
      it "performs light validation on source lists" do
        expect do
          CSP.validate_config!(default_src: %w(self none inline eval))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end
    end

    describe "#combine_policies" do
      it "combines the default-src value with the override if the directive was unconfigured" do
        combined_config = CSP.combine_policies(Configuration.default.csp, script_src: %w(anothercdn.com))
        csp = ContentSecurityPolicy.new(combined_config)
        expect(csp.name).to eq(CSP::HEADER_NAME)
        expect(csp.value).to eq("default-src https:; script-src https: anothercdn.com")
      end

      it "overrides the report_only flag" do
        Configuration.default do |config|
          config.csp = {
            default_src: %w('self'),
            report_only: false
          }
        end
        combined_config = CSP.combine_policies(Configuration.get.csp, report_only: true)
        csp = ContentSecurityPolicy.new(combined_config, USER_AGENTS[:firefox])
        expect(csp.name).to eq(CSP::REPORT_ONLY)
      end

      it "overrides the :block_all_mixed_content flag" do
        Configuration.default do |config|
          config.csp = {
            default_src: %w(https:),
            block_all_mixed_content: false
          }
        end
        combined_config = CSP.combine_policies(Configuration.get.csp, block_all_mixed_content: true)
        csp = ContentSecurityPolicy.new(combined_config)
        expect(csp.value).to eq("default-src https:; block-all-mixed-content")
      end

      it "raises an error if appending to a OPT_OUT policy" do
        Configuration.default do |config|
          config.csp = OPT_OUT
        end
        expect do
          CSP.combine_policies(Configuration.get.csp, script_src: %w(anothercdn.com))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end
    end

    describe "#value" do
      it "discards 'none' values if any other source expressions are present" do
        csp = ContentSecurityPolicy.new(default_opts.merge(frame_src: %w('self' 'none')))
        expect(csp.value).not_to include("'none'")
      end

      it "discards source expressions besides unsafe-* expressions when * is present" do
        csp = ContentSecurityPolicy.new(default_src: %w(* 'unsafe-inline' 'unsafe-eval' http: https: example.org))
        expect(csp.value).to eq("default-src * 'unsafe-inline' 'unsafe-eval'")
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

      it "removes nil from source lists" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org", nil])
        expect(csp.value).to eq("default-src example.org")
      end

      it "deduplicates any source expressions" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org example.org example.org))
        expect(csp.value).to eq("default-src example.org")
      end

      context "browser sniffing" do
        let (:complex_opts) do
          ContentSecurityPolicy::ALL_DIRECTIVES.each_with_object({}) { |directive, hash| hash[directive] = %w('self') }
            .merge(block_all_mixed_content: true, reflected_xss: "block")
            .merge(script_src: %w('self'), script_nonce: 123456)
        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:chrome])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; report-uri 'self'")
        end

        it "does not filter any directives for Opera" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:opera])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; block-all-mixed-content; child-src 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; plugin-types 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; report-uri 'self'")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox])
          expect(policy.value).to eq("default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'nonce-123456'; style-src 'self'; report-uri 'self'")
        end

        it "adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari6])
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; report-uri 'self'")
        end
      end
    end
  end
end
