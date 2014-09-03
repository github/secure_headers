require 'rack'

module SecureHeaders
  class ScriptHash
     def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, response = @app.call(env)
      script_hashes = env['script_hashes']

      if headers["Content-Type"] && headers["Content-Type"].include?("text/html") && script_hashes.present?
        ['Content-Security-Policy-Report-Only', 'Content-Security-Policy'].each do |header_name|
          if csp = env[header_name]
            csp.config[:script_src] = csp.config[:script_src] + script_hashes.map {|hash| hash_source_value(hash)}
            headers[header_name] = csp.value
          end
        end
      end

      [status, headers, response]
    end

    def hash_source_value(hash, format = "sha256", delimeter = "-", wrapper = "'")
      wrapper + format + delimeter + hash + wrapper
    end
  end

  module ScriptHashHelpers
    def generate_inline_script_hashes(filename)
      file = File.read(filename)
      hashes = []
      file.gsub(INLINE_SCRIPT_REGEX) do
        inline_script = Regexp.last_match.captures[-2]
        if (filename =~ /\.mustache\Z/ && inline_script =~ /\{\{.*\}\}/) || (filename =~ /\.erb\Z/ && inline_script =~ /<%.*%>/)
          puts "Looks like there's some dynamic content inside of a script tag :-/"
          puts "That pretty much means the hash value will never match."
          puts "Code: " + inline_script
          puts "=" * 20
        end

        hashes << sha256_base64_digest(inline_script)
      end

      hashes
    end

    def sha256_base64_digest(inline_script)
      # doesn't work on 1.8.7 :(
      # base64_193 = Digest::SHA256.base64digest(inline_script)
      [[Digest::SHA256.hexdigest(inline_script)].pack("H*")].pack("m").chomp
    end
  end
end