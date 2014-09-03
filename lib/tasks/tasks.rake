INLINE_SCRIPT_REGEX = /(<script([ ]*(?!src)([\w\-])+=([\"\'])[^\"\']+\4)*[ ]*>)(.*?)(<\/script>)/mx
SCRIPT_HASH_CONFIG_FILE = 'config/script_hashes.yml'

namespace :secure_headers do
  require File.expand_path(File.join('..','..','secure_Headers','script_hash.rb'), __FILE__)
  include SecureHeaders::ScriptHashHelpers

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