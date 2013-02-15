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

      def build_impl_specific_directives(default)
        build_firefox_specific_preamble(default) || ''
      end

      def build_firefox_specific_preamble(default_src_value)
        header_value = ''
        header_value += "allow #{default_src_value.join(" ")}; " if default_src_value.any?

        options_directive = build_options_directive
        header_value += "options #{options_directive.join(" ")}; " if options_directive.any?
        header_value
      end

      # moves inline/eval values from script-src to options
      # discards those values in the style-src directive
      def build_options_directive
        options_directive = []
        config.each do |directive, val|
          next if val.is_a?(String)
          new_val = []
          val.each do |token|
            if ['inline-script', 'eval-script'].include?(token)
              # Firefox does not support blocking inline styles ATM
              # https://bugzilla.mozilla.org/show_bug.cgi?id=763879
              unless directive?(directive, "style_src") || options_directive.include?(token)
                options_directive << token
              end
            else
              new_val << token
            end
          end
          config[directive] = new_val
        end

        options_directive
      end
    end
  end
end
