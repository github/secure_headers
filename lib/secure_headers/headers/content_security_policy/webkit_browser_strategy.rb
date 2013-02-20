module SecureHeaders
  class ContentSecurityPolicy
    class WebkitBrowserStrategy < BrowserStrategy
      def base_name
        SecureHeaders::ContentSecurityPolicy::WEBKIT_CSP_HEADER_NAME
      end
    end
  end
end
