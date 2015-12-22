module SecureHeaders
  module ViewHelpers
    # Public: create a style tag using the content security policy nonce.
    # Instructs secure_headers to append a nonce to style/script-src directives.
    #
    # Returns an html-safe style tag with the nonce attribute.
    def nonced_style_tag(content_or_options = {}, &block)
      nonced_tag(:style, content_or_options, block)
    end

    # Public: create a script tag using the content security policy nonce.
    # Instructs secure_headers to append a nonce to style/script-src directives.
    #
    # Returns an html-safe script tag with the nonce attribute.
    def nonced_javascript_tag(content_or_options = {}, &block)
      nonced_tag(:script, content_or_options, block)
    end

    # Public: use the content security policy nonce for this request directly.
    # Instructs secure_headers to append a nonce to style/script-src directives.
    #
    # Returns a non-html-safe nonce value.
    def content_security_policy_nonce(type)
      case type
      when :script
        SecureHeaders.content_security_policy_script_nonce(@_request)
      when :style
        SecureHeaders.content_security_policy_style_nonce(@_request)
      end
    end

    private

    def nonced_tag(type, content_or_options, block)
      options = {}
      content = if block
        options = content_or_options
        capture(&block)
      else
        content_or_options.html_safe # :'(
      end
      content_tag type, content, options.merge(nonce: content_security_policy_nonce(type))
    end
  end
end

module ActionView #:nodoc:
  class Base #:nodoc:
    include SecureHeaders::ViewHelpers
  end
end
