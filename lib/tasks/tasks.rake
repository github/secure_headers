INLINE_SCRIPT_REGEX = /(<script(\s*(?!src)([\w\-])+=([\"\'])[^\"\']+\4)*\s*>)(.*?)<\/script>/mx
INLINE_HASH_HELPER_REGEX = /<%=\s?hashed_javascript_tag(.*?)\s+do\s?%>(.*?)<%\s*end\s*%>/mx
SCRIPT_HASH_CONFIG_FILE = 'config/script_hashes.yml'

namespace :secure_headers do
  include SecureHeaders::HashHelper

  def is_erb?(filename)
    filename =~ /\.erb\Z/
  end

  def generate_inline_script_hashes(filename)
    file = File.read(filename)
    hashes = []

    [INLINE_SCRIPT_REGEX, INLINE_HASH_HELPER_REGEX].each do |regex|
      file.gsub(regex) do # TODO don't use gsub
        inline_script = Regexp.last_match.captures.last
        if (filename =~ /\.mustache\Z/ && inline_script =~ /\{\{.*\}\}/) || (is_erb?(filename) && inline_script =~ /<%.*%>/)
          puts "Looks like there's some dynamic content inside of a script tag :-/"
          puts "That pretty much means the hash value will never match."
          puts "Code: " + inline_script
          puts "=" * 20
        end

        hashes << hash_source(inline_script)
      end
    end

    hashes
  end

  task :generate_hashes do |t, args|
    script_hashes = {}
    Dir.glob("app/{views,templates}/**/*.{erb,mustache}") do |filename|
      hashes = generate_inline_script_hashes(filename)
      if hashes.any?
        script_hashes[filename] = hashes
      end
    end

    File.open(SCRIPT_HASH_CONFIG_FILE, 'w') do |file|
      file.write(script_hashes.to_yaml)
    end

    puts "Script hashes from " + script_hashes.keys.size.to_s + " files added to #{SCRIPT_HASH_CONFIG_FILE}"
  end
end
