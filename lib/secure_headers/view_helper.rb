module SecureHeaders
  class UnexpectedHashedScriptException < StandardError

  end

  module ViewHelpers
    include SecureHeaders::HashHelper
    SECURE_HEADERS_RAKE_TASK = "rake secure_headers:generate_hashes"

    def nonced_style_tag(content = nil, options = nil, &block)
      nonced_tag(content, :style, options, block)
    end

    def nonced_javascript_tag(content = nil, options = nil, &block)
      nonced_tag(content, :script, options, block)
    end

    def hashed_javascript_tag(raise_error_on_unrecognized_hash = false, &block)
      content = capture(&block)

      if ['development', 'test'].include?(ENV["RAILS_ENV"])
        hash_value = hash_source(content)
        file_path = File.join('app', 'views', self.instance_variable_get(:@virtual_path) + '.html.erb')
        # TODO append hashes to csp config
        # script_hashes = request.env[SCRIPT_HASHES_KEY][file_path]
        unless script_hashes && script_hashes.include?(hash_value)
          message = unexpected_hash_error_message(file_path, hash_value, content)
          if raise_error_on_unrecognized_hash
            raise UnexpectedHashedScriptException.new(message)
          else
            # request.env[HASHES_ENV_KEY] = (request.env[HASHES_ENV_KEY] || []) << hash_value
          end
        end
      end

      content_tag :script, content
    end

    private

    def nonced_tag(content, type, options, block)
      content = if block
        capture(&block)
      else
        content.html_safe # :'(
      end

      content_tag type, content, options.merge(nonce: content_security_policy_nonce)
    end

    def unexpected_hash_error_message(file_path, hash_value, content)
      <<-EOF
\n\n*** WARNING: Unrecognized hash in #{file_path}!!! Value: #{hash_value} ***
<script>#{content}</script>
*** This is fine in dev/test, but will raise exceptions in production. ***
*** Run #{SECURE_HEADERS_RAKE_TASK} or add the following to config/script_hashes.yml:***
#{file_path}:
- #{hash_value}\n\n
      EOF
    end
  end
end

module ActionView #:nodoc:
  class Base #:nodoc:
    include SecureHeaders::ViewHelpers
  end
end
