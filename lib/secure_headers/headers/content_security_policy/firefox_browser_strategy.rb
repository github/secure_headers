module SecureHeaders
  class ContentSecurityPolicy
    class FirefoxBrowserStrategy < BrowserStrategy
      def base_name
        FIREFOX_CSP_HEADER_NAME
      end
    end
  end
end
