require "forwardable"

module SecureHeaders
  class ContentSecurityPolicy
    class BrowserStrategy
      extend Forwardable

      def_delegators :@content_security_policy, :browser, :experimental, :enforce, :config

      def self.build(content_security_policy)
        browser = content_security_policy.browser
        klass = if browser.ie?
          IeBrowserStrategy
        elsif browser.firefox?
          FirefoxBrowserStrategy
        else
          WebkitBrowserStrategy
        end

        klass.new content_security_policy
      end

      def initialize(content_security_policy)
        @content_security_policy = content_security_policy
      end

      def base_name
        SecureHeaders::ContentSecurityPolicy::STANDARD_HEADER_NAME
      end

      def name
        base = base_name
        if !enforce || experimental
          base += "-Report-Only"
        end
        base
      end

      def csp_header
        SecureHeaders::ContentSecurityPolicy::WEBKIT_CSP_HEADER
      end

      def directives
        SecureHeaders::ContentSecurityPolicy::WEBKIT_DIRECTIVES
      end

      def filter_unsupported_directives(config)
        config = config.dup
        config.delete(:frame_ancestors)
        config
      end

      def translate_inline_or_eval val
        val == 'inline' ? "'unsafe-inline'" : "'unsafe-eval'"
      end

      def build_impl_specific_directives(default)
        if default.any?
          "default-src #{default.join(" ")}; "
        else
          ""
        end
      end

      def normalize_reporting_endpoint?
        false
      end

      def add_missing_extension_values
        # noop except for chrome for now
      end
    end
  end
end
