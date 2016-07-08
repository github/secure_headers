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
        csp = ContentSecurityPolicy.new(default_opts.merge(child_src: %w('self' 'none')))
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

      it "does add a boolean directive if the value is true" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org"], block_all_mixed_content: true, upgrade_insecure_requests: true)
        expect(csp.value).to eq("default-src example.org; block-all-mixed-content; upgrade-insecure-requests")
      end

      it "does not add a boolean directive if the value is false" do
        csp = ContentSecurityPolicy.new(default_src: ["https://example.org"], block_all_mixed_content: true, upgrade_insecure_requests: false)
        expect(csp.value).to eq("default-src example.org; block-all-mixed-content")
      end

      it "deduplicates any source expressions" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org example.org example.org))
        expect(csp.value).to eq("default-src example.org")
      end

      it "emits a warning when using frame-src" do
        expect(Kernel).to receive(:warn).with(/:frame_src is deprecated, use :child_src instead./)
        ContentSecurityPolicy.new(default_src: %w('self'), frame_src: %w('self')).value
      end

      it "emits a warning when child-src and frame-src are supplied but are not equal" do
        expect(Kernel).to receive(:warn).with(/both :child_src and :frame_src supplied and do not match./)
        ContentSecurityPolicy.new(default_src: %w('self'), child_src: %w(child-src.com), frame_src: %w(frame-src,com)).value
      end

      it "will still set inconsistent child/frame-src values to be less surprising" do
        expect(Kernel).to receive(:warn).at_least(:once)
        firefox = ContentSecurityPolicy.new({default_src: %w('self'), child_src: %w(child-src.com), frame_src: %w(frame-src,com)}, USER_AGENTS[:firefox]).value
        firefox_transitional = ContentSecurityPolicy.new({default_src: %w('self'), child_src: %w(child-src.com), frame_src: %w(frame-src,com)}, USER_AGENTS[:firefox46]).value
        expect(firefox).not_to eq(firefox_transitional)
        expect(firefox).to match(/frame-src/)
        expect(firefox).not_to match(/child-src/)
        expect(firefox_transitional).to match(/child-src/)
        expect(firefox_transitional).not_to match(/frame-src/)
      end

      context "browser sniffing" do
        let (:complex_opts) do
          (ContentSecurityPolicy::ALL_DIRECTIVES - [:frame_src]).each_with_object({}) do |directive, hash|
            hash[directive] = ["#{directive.to_s.gsub("_", "-")}.com"]
          end.merge({
            block_all_mixed_content: true,
            upgrade_insecure_requests: true,
            reflected_xss: "block",
            script_src: %w(script-src.com),
            script_nonce: 123456
          })
        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:chrome])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; block-all-mixed-content; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; plugin-types plugin-types.com; sandbox sandbox.com; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "does not filter any directives for Opera" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:opera])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; block-all-mixed-content; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; plugin-types plugin-types.com; sandbox sandbox.com; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; frame-src child-src.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox sandbox.com; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "filters blocked-all-mixed-content, frame-src, and plugin-types for firefox 46 and higher" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox46])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox sandbox.com; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "child-src value is copied to frame-src, adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for Edge" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:edge])
          expect(policy.value).to eq("default-src default-src.com; connect-src connect-src.com; font-src font-src.com; frame-src child-src.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox sandbox.com; script-src script-src.com 'unsafe-inline'; style-src style-src.com; report-uri report-uri.com")
        end

        it "child-src value is copied to frame-src, adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari6])
          expect(policy.value).to eq("default-src default-src.com; connect-src connect-src.com; font-src font-src.com; frame-src child-src.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox sandbox.com; script-src script-src.com 'unsafe-inline'; style-src style-src.com; report-uri report-uri.com")
        end
      end
    end
  end
end
