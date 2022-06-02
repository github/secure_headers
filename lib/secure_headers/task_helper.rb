# frozen_string_literal: true

module SecureHeaders
  module TaskHelper
    include SecureHeaders::HashHelper

    INLINE_SCRIPT_REGEX = /(<script(\s*(?!src)([\w\-])+=([\"\'])[^\"\']+\4)*\s*>)(.*?)<\/script>/mx
    INLINE_STYLE_REGEX = /(<style[^>]*>)(.*?)<\/style>/mx
    INLINE_HASH_SCRIPT_HELPER_REGEX = /<%=\s?hashed_javascript_tag(.*?)\s+do\s?%>(.*?)<%\s*end\s*%>/mx
    INLINE_HASH_STYLE_HELPER_REGEX = /<%=\s?hashed_style_tag(.*?)\s+do\s?%>(.*?)<%\s*end\s*%>/mx

    def generate_inline_script_hashes(filename)
      hashes = []

      hashes.concat find_inline_content(filename, INLINE_SCRIPT_REGEX, false)
      hashes.concat find_inline_content(filename, INLINE_HASH_SCRIPT_HELPER_REGEX, true)

      hashes
    end

    def generate_inline_style_hashes(filename)
      hashes = []

      hashes.concat find_inline_content(filename, INLINE_STYLE_REGEX, false)
      hashes.concat find_inline_content(filename, INLINE_HASH_STYLE_HELPER_REGEX, true)

      hashes
    end

    def dynamic_content?(filename, inline_script)
      !!(
        (is_mustache?(filename) && inline_script =~ /\{\{.*\}\}/) ||
        (is_erb?(filename) && inline_script =~ /<%.*%>/)
        )
    end

    private

    def find_inline_content(filename, regex, strip_trailing_whitespace)
      hashes = []
      file = File.read(filename)
      file.scan(regex) do # TODO don't use gsub
        inline_script = Regexp.last_match.captures.last
        inline_script.gsub!(/(\r?\n)[\t ]+\z/, '\1') if strip_trailing_whitespace
        if dynamic_content?(filename, inline_script)
          puts "Looks like there's some dynamic content inside of a tag :-/"
          puts "That pretty much means the hash value will never match."
          puts "Code: " + inline_script
          puts "=" * 20
        end

        hashes << hash_source(inline_script)
      end
      hashes
    end

    def is_erb?(filename)
      filename =~ /\.erb\Z/
    end

    def is_mustache?(filename)
      filename =~ /\.mustache\Z/
    end
  end
end
