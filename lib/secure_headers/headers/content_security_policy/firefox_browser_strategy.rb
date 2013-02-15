module SecureHeaders
  class ContentSecurityPolicy
    class FirefoxBrowserStrategy < BrowserStrategy
      def base_name
        FIREFOX_CSP_HEADER_NAME
      end

      def csp_header
        FIREFOX_CSP_HEADER
      end

      def directives
        FIREFOX_DIRECTIVES
      end
    end
  end
end
