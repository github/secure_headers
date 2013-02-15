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

      def filter_unsupported_directives(config)
        config = config.dup
        config[:xhr_src] = config.delete(:connect_src) if config[:connect_src]
        config
      end

      def translate_inline_or_eval val
        val == 'inline' ? 'inline-script' : 'eval-script'
      end
    end
  end
end
