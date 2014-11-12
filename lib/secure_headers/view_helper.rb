module SecureHeaders
  class UnexpectedHashedScriptException < StandardError

  end

  module ViewHelpers
    include SecureHeaders::HashHelper
    SECURE_HEADERS_RAKE_TASK = "rake secure_headers:generate_hashes"

    def nonced_javascript_tag(content = nil, &block)
      content = if block_given?
        capture(&block)
      else
        content.html_safe # :'(
      end

      content_tag :script, content, :nonce => @content_security_policy_nonce
    end

    def hashed_javascript_tag(content_or_config = nil, raise_error_on_unrecognized_hash = false, &block)
      content = if block_given?
        raise_error_on_unrecognized_hash = content_or_config
        capture(&block)
      else
        content_or_config.html_safe # :'(
      end

      if ['development', 'test'].include?(ENV["RAILS_ENV"])
        hash_value = hash_source(content)
        file_path = File.join('app', 'views', self.instance_variable_get(:@virtual_path) + '.html.erb')
        script_hashes = controller.instance_variable_get(:@script_hashes)[file_path]
        unless script_hashes && script_hashes.include?(hash_value)
          message = unexpected_hash_error_message(file_path, hash_value, content)
          if raise_error_on_unrecognized_hash
            raise UnexpectedHashedScriptException.new(message)
          else
            puts message
            request.env[HASHES_ENV_KEY] = (request.env[HASHES_ENV_KEY] || []) << hash_value
          end
        end
      end

      content_tag :script, content
    end

    private

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
  module Helpers #:nodoc:
    include SecureHeaders::ViewHelpers
  end
end
