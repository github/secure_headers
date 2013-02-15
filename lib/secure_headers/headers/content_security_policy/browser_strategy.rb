require "forwardable"

module SecureHeaders
  class ContentSecurityPolicy
    class BrowserStrategy
      extend Forwardable

      def_delegators :@content_security_policy, :browser, :experimental, :enforce

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
        STANDARD_HEADER_NAME
      end

      def name
        base = base_name
        if !enforce || experimental
          base += "-Report-Only"
        end
        base
      end
    end
  end
end
