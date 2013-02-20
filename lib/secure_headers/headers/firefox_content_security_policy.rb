module SecureHeaders
  class FirefoxContentSecurityPolicy < ContentSecurityPolicy
    module Constants
      FIREFOX_CSP_HEADER = "options eval-script inline-script; allow https://* data:; frame-src https://* about: javascript:; img-src chrome-extension:"
      FIREFOX_CSP_HEADER_NAME = 'X-Content-Security-Policy'
      FF_CSP_ENDPOINT = "/content_security_policy/forward_report"
      FIREFOX_DIRECTIVES = ContentSecurityPolicy::DIRECTIVES + [:xhr_src, :frame_ancestors] - [:connect_src]
    end
    include Constants

    def after_configure
      super
      normalize_reporting_endpoint
      filter_unsupported_directives
    end

    def base_name
      FIREFOX_CSP_HEADER_NAME
    end

    def directives
      FIREFOX_DIRECTIVES
    end

    def csp_header
      return supports_standard? ? STANDARD_CSP_HEADER : FIREFOX_CSP_HEADER
    end

    private

    def supports_standard?
      browser.version.to_i >= 18
    end

    def build_impl_specific_directives
      header_value = ""
      default = expect_directive_value(:default_src)
      header_value += build_preamble(default) || ''
      header_value
    end

    def build_preamble(default_src_value)
      header_value = ''
      if supports_standard?
        header_value += "default-src #{default_src_value.join(" ")}; " if default_src_value.any?
      elsif default_src_value
        header_value += "allow #{default_src_value.join(" ")}; " if default_src_value.any?
      end

      options_directive = build_options_directive
      header_value += "options #{options_directive.join(" ")}; " if options_directive.any?
      header_value
    end

    def filter_unsupported_directives
      @config[:xhr_src] = @config.delete(:connect_src) if @config[:connect_src]
    end

    # inline/eval => impl-specific values
    def translate_inline_or_eval val
      # can't use supports_standard because FF18 does not support this part of the standard.
      val == 'inline' ? 'inline-script' : 'eval-script'
    end

    # if we have a forwarding endpoint setup and we are not on the same origin as our report_uri
    # or only a path was supplied (in which case we assume cross-host)
    # we need to forward the request for Firefox.
    def normalize_reporting_endpoint
      # can't use supports_standard because FF18 does not support cross-origin posting.
      if (!same_origin? || URI.parse(report_uri).host.nil?)
        if @forward_endpoint
          @report_uri = FF_CSP_ENDPOINT
        else
          @report_uri = nil
        end
      end
    end
  end
end
