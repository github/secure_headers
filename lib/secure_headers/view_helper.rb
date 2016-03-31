module SecureHeaders
  module ViewHelpers
    include SecureHeaders::HashHelper
    SECURE_HEADERS_RAKE_TASK = "rake secure_headers:generate_hashes"

    class UnexpectedHashedScriptException < StandardError; end

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

    def hashed_javascript_tag(raise_error_on_unrecognized_hash = nil, &block)
      if raise_error_on_unrecognized_hash.nil?
        raise_error_on_unrecognized_hash = !['development', 'test'].include?(ENV["RAILS_ENV"])
      end
      content = capture(&block)

      hash_value = hash_source(content)
      file_path = File.join('app', 'views', self.instance_variable_get(:@virtual_path) + '.html.erb')
      script_hashes = Configuration.instance_variable_get(:@script_hashes)[file_path]
      unless script_hashes && script_hashes.include?(hash_value)
        message = unexpected_hash_error_message(file_path, hash_value, content)
        if raise_error_on_unrecognized_hash
          raise UnexpectedHashedScriptException.new(message)
        else
          warn message
        end
      end

      SecureHeaders.append_content_security_policy_directives(request, script_src: [hash_value])

      content_tag :script, content
    end

    private

    def unexpected_hash_error_message(file_path, hash_value, content)
      <<-EOF
\n\n*** WARNING: Unrecognized hash in #{file_path}!!! Value: #{hash_value} ***
<script>#{content}</script>
*** Run #{SECURE_HEADERS_RAKE_TASK} or add the following to config/script_hashes.yml:***
#{file_path}:
- #{hash_value}\n\n
      EOF
    end

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
