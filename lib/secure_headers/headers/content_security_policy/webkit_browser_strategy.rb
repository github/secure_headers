module SecureHeaders
  class ContentSecurityPolicy
    class WebkitBrowserStrategy < BrowserStrategy
      def base_name
        SecureHeaders::ContentSecurityPolicy::WEBKIT_CSP_HEADER_NAME
      end

      def add_missing_extension_values
        directives.each do |directive|
          next unless config[directive]
          if !config[directive].include?('chrome-extension:')
            config[directive] << 'chrome-extension:'
          end
        end
      end
    end
  end
end
