require 'spec_helper'

module SecureHeaders
  describe PolicyManagement do
    let (:default_opts) do
      {
        default_src: %w(https:),
        img_src: %w(https: data:),
        script_src: %w('unsafe-inline' 'unsafe-eval' https: data:),
        style_src: %w('unsafe-inline' https: about:),
        report_uri: %w(/csp_report)
      }
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
          child_src: %w('self' *.twimg.com itunes.apple.com),
          connect_src: %w(wss:),
          font_src: %w('self' data:),
          img_src: %w(mycdn.com data:),
          media_src: %w(utoob.com),
          object_src: %w('self'),
          script_src: %w('self'),
          style_src: %w('unsafe-inline'),
          base_uri: %w('self'),
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

      it "combines directives where the original value is nil and the hash is frozen" do
        Configuration.default do |config|
          config.csp = {
            default_src: %w('self'),
            report_only: false
          }.freeze
        end
        report_uri = "https://report-uri.io/asdf"
        combined_config = CSP.combine_policies(Configuration.get.csp, report_uri: [report_uri])
        csp = ContentSecurityPolicy.new(combined_config, USER_AGENTS[:firefox])
        expect(csp.value).to include("report-uri #{report_uri}")
      end

      it "does not combine the default-src value for directives that don't fall back to default sources" do
        Configuration.default do |config|
          config.csp = {
            default_src: %w('self'),
            report_only: false
          }.freeze
        end
        non_default_source_additions = CSP::NON_FETCH_SOURCES.each_with_object({}) do |directive, hash|
          hash[directive] = %w("http://example.org)
        end
        combined_config = CSP.combine_policies(Configuration.get.csp, non_default_source_additions)

        CSP::NON_FETCH_SOURCES.each do |directive|
          expect(combined_config[directive]).to eq(%w("http://example.org))
        end

         ContentSecurityPolicy.new(combined_config, USER_AGENTS[:firefox]).value
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
  end
end
