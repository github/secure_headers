module SecureHeaders
  class UnexpectedHashedScriptException < StandardError

  end

  module ViewHelpers
    include SecureHeaders::HashHelper
    SECURE_HEADERS_RAKE_TASK = "rake secure_headers:generate_hashes"

    def nonced_style_tag(content_or_options, &block)
      nonced_tag(:style, content_or_options, block)
    end

    def nonced_javascript_tag(content_or_options, &block)
      nonced_tag(:script, content_or_options, block)
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
      content_tag type, content, options.merge(nonce: @_controller.content_security_policy_nonce)
    end
  end
end

module ActionView #:nodoc:
  class Base #:nodoc:
    include SecureHeaders::ViewHelpers
  end
end
