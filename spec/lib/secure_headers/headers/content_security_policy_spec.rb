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

    describe "#validate_config!" do
      it "accepts all keys" do
        # (pulled from README)
        config = {
          # "meta" values. these will shaped the header, but the values are not included in the header.
          report_only:  true,     # default: false
          preserve_schemes: true, # default: false. Schemes are removed from host sources to save bytes and discourage mixed content.

          # directive values: these values will directly translate into source directives
          default_src: %w(https: 'self'),
          frame_src: %w('self' *.twimg.com itunes.apple.com),
          connect_src: %w(wws:),
          font_src: %w('self' data:),
          img_src: %w(mycdn.com data:),
          media_src: %w(utoob.com),
          object_src: %w('self'),
          script_src: %w('self'),
          style_src: %w('unsafe-inline'),
          base_uri: %w('self'),
          child_src: %w('self'),
          form_action: %w('self' github.com),
          frame_ancestors: %w('none'),
          plugin_types: %w(application/x-shockwave-flash),
          block_all_mixed_content: true, # see [http://www.w3.org/TR/mixed-content/](http://www.w3.org/TR/mixed-content/)
          upgrade_insecure_requests: true, # see https://www.w3.org/TR/upgrade-insecure-requests/
          report_uri: %w(https://example.com/uri-directive)
        }

        CSP.validate_config!(config)
      end

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

      it "requires :preserve_schemes to be a truthy value" do
        expect do
          CSP.validate_config!(default_opts.merge(preserve_schemes: "steve"))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :block_all_mixed_content to be a boolean value" do
        expect do
          CSP.validate_config!(default_opts.merge(block_all_mixed_content: "steve"))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires :upgrade_insecure_requests to be a boolean value" do
        expect do
          CSP.validate_config!(default_opts.merge(upgrade_insecure_requests: "steve"))
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "requires all source lists to be an array of strings" do
        expect do
          CSP.validate_config!(default_src: "steve")
        end.to raise_error(ContentSecurityPolicyConfigError)
      end

      it "allows nil values" do
        expect do
          CSP.validate_config!(default_src: %w('self'), script_src: ["https:", nil])
        end.to_not raise_error
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

    describe "#idempotent_additions?" do
      specify { expect(ContentSecurityPolicy.idempotent_additions?(OPT_OUT, script_src: %w(b.com))).to be false }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: %w(c.com))).to be false }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, style_src: %w(b.com))).to be false }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: %w(a.com b.com c.com))).to be false }

      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: %w(b.com))).to be true }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: %w(b.com a.com))).to be true }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: %w())).to be true }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, script_src: [nil])).to be true }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, style_src: [nil])).to be true }
      specify { expect(ContentSecurityPolicy.idempotent_additions?({script_src: %w(a.com b.com)}, style_src: nil)).to be true }
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

        it "adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari6])
          expect(policy.value).to eq("default-src 'self'; connect-src 'self'; font-src 'self'; frame-src 'self'; img-src 'self'; media-src 'self'; object-src 'self'; sandbox 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; report-uri 'self'")
        end
      end
    end
  end
end
