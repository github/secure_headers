# frozen_string_literal: true
require "spec_helper"

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
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(report_only: true)).name).to eq(ContentSecurityPolicyReportOnlyConfig::HEADER_NAME) }
      end

      context "when in enforce mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts).name).to eq(ContentSecurityPolicyConfig::HEADER_NAME) }
      end
    end

    describe "#value" do
      it "uses a safe but non-breaking default value" do
        expect(ContentSecurityPolicy.new.value).to eq("default-src https:; form-action 'self'; img-src https: data: 'self'; object-src 'none'; script-src https:; style-src 'self' 'unsafe-inline' https:")
      end

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

      it "does not build directives with a value of OPT_OUT (and bypasses directive requirements)" do
        csp = ContentSecurityPolicy.new(default_src: %w(https://example.org), script_src: OPT_OUT)
        expect(csp.value).to eq("default-src example.org")
      end

      it "does not remove schemes from report-uri values" do
        csp = ContentSecurityPolicy.new(default_src: %w(https:), report_uri: %w(https://example.org))
        expect(csp.value).to eq("default-src https:; report-uri https://example.org")
      end

      it "does not remove schemes when :preserve_schemes is true" do
        csp = ContentSecurityPolicy.new(default_src: %w(https://example.org), preserve_schemes: true)
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

      it "creates maximally strict sandbox policy when passed no sandbox token values" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org), sandbox: [])
        expect(csp.value).to eq("default-src example.org; sandbox")
      end

      it "creates maximally strict sandbox policy when passed true" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org), sandbox: true)
        expect(csp.value).to eq("default-src example.org; sandbox")
      end

      it "creates sandbox policy when passed valid sandbox token values" do
        csp = ContentSecurityPolicy.new(default_src: %w(example.org), sandbox: %w(allow-forms allow-scripts))
        expect(csp.value).to eq("default-src example.org; sandbox allow-forms allow-scripts")
      end

      it "does not emit a warning when using frame-src" do
        expect(Kernel).to_not receive(:warn)
        ContentSecurityPolicy.new(default_src: %w('self'), frame_src: %w('self')).value
      end

      it "raises an error when child-src and frame-src are supplied but are not equal" do
        expect {
          ContentSecurityPolicy.new(default_src: %w('self'), child_src: %w(child-src.com), frame_src: %w(frame-src,com)).value
        }.to raise_error(ArgumentError)
      end

      it "supports strict-dynamic" do
        csp = ContentSecurityPolicy.new({default_src: %w('self'), script_src: [ContentSecurityPolicy::STRICT_DYNAMIC], script_nonce: 123456}, USER_AGENTS[:chrome])
        expect(csp.value).to eq("default-src 'self'; script-src 'strict-dynamic' 'nonce-123456'")
      end

      context "browser sniffing" do
        let (:complex_opts) do
          (ContentSecurityPolicy::ALL_DIRECTIVES - [:frame_src]).each_with_object({}) do |directive, hash|
            hash[directive] = ["#{directive.to_s.gsub("_", "-")}.com"]
          end.merge({
            block_all_mixed_content: true,
            upgrade_insecure_requests: true,
            script_src: %w(script-src.com),
            script_nonce: 123456,
            sandbox: %w(allow-forms),
            plugin_types: %w(application/pdf)
          })
        end

        it "does not filter any directives for Chrome" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:chrome])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; block-all-mixed-content; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; manifest-src manifest-src.com; media-src media-src.com; object-src object-src.com; plugin-types application/pdf; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; worker-src worker-src.com; report-uri report-uri.com")
        end

        it "does not filter any directives for Opera" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:opera])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; block-all-mixed-content; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; manifest-src manifest-src.com; media-src media-src.com; object-src object-src.com; plugin-types application/pdf; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; worker-src worker-src.com; report-uri report-uri.com")
        end

        it "filters blocked-all-mixed-content, child-src, and plugin-types for firefox" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; frame-src child-src.com; img-src img-src.com; manifest-src manifest-src.com; media-src media-src.com; object-src object-src.com; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "filters blocked-all-mixed-content, frame-src, and plugin-types for firefox 46 and higher" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:firefox46])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; manifest-src manifest-src.com; media-src media-src.com; object-src object-src.com; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end

        it "child-src value is copied to frame-src, adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for Edge" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:edge])
          expect(policy.value).to eq("default-src default-src.com; connect-src connect-src.com; font-src font-src.com; frame-src child-src.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox allow-forms; script-src script-src.com 'unsafe-inline'; style-src style-src.com; report-uri report-uri.com")
        end

        it "child-src value is copied to frame-src, adds 'unsafe-inline', filters base-uri, blocked-all-mixed-content, upgrade-insecure-requests, child-src, form-action, frame-ancestors, nonce sources, hash sources, and plugin-types for safari" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari6])
          expect(policy.value).to eq("default-src default-src.com; connect-src connect-src.com; font-src font-src.com; frame-src child-src.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; sandbox allow-forms; script-src script-src.com 'unsafe-inline'; style-src style-src.com; report-uri report-uri.com")
        end

        it "adds 'unsafe-inline', filters  blocked-all-mixed-content, upgrade-insecure-requests, nonce sources, and hash sources for safari 10 and higher" do
          policy = ContentSecurityPolicy.new(complex_opts, USER_AGENTS[:safari10])
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; child-src child-src.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; img-src img-src.com; media-src media-src.com; object-src object-src.com; plugin-types application/pdf; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; report-uri report-uri.com")
        end

        it "falls back to standard Firefox defaults when the useragent version is not present" do
          ua = USER_AGENTS[:firefox].dup
          allow(ua).to receive(:version).and_return(nil)
          policy = ContentSecurityPolicy.new(complex_opts, ua)
          expect(policy.value).to eq("default-src default-src.com; base-uri base-uri.com; connect-src connect-src.com; font-src font-src.com; form-action form-action.com; frame-ancestors frame-ancestors.com; frame-src child-src.com; img-src img-src.com; manifest-src manifest-src.com; media-src media-src.com; object-src object-src.com; sandbox allow-forms; script-src script-src.com 'nonce-123456'; style-src style-src.com; upgrade-insecure-requests; report-uri report-uri.com")
        end
      end
    end
  end
end
