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

    def hashed_javascript_tag(raise_error_on_unrecognized_hash = false, &block)
      content = capture(&block)

      if ['development', 'test'].include?(ENV["RAILS_ENV"])
        hash_value = hash_source(content)
        file_path = File.join('app', 'views', self.instance_variable_get(:@virtual_path) + '.html.erb')
        script_hashes = controller.instance_variable_get(:@script_hashes)[file_path]
        unless script_hashes && script_hashes.include?(hash_value)
          if raise_error_on_unrecognized_hash
            raise UnexpectedHashedScriptException.new("Unknown script hash value (#{hash_value}). Run #{SECURE_HEADERS_RAKE_TASK}. #{file_path}:\n#{content}")
          else
            puts "\n\n*** WARNING: Unrecognized hash!!! Value: #{hash_value} ***"
            puts "<script>#{content}</script>"
            puts "*** This is fine in dev/test, but will raise exceptions in production. ***"
            puts "*** Run #{SECURE_HEADERS_RAKE_TASK} ***\n\n"
            request.env[HASHES_ENV_KEY] = (request.env[HASHES_ENV_KEY] || []) << hash_value
          end
        end
      end

      content_tag :script, content
    end
  end
end

module ActionView #:nodoc:
  module Helpers #:nodoc:
    include SecureHeaders::ViewHelpers
  end
end
