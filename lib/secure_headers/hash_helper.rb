module SecureHeaders
  module HashHelper
    def hash_source(inline_script, digest = :SHA256)
      base64_hashed_content = Digest.const_get(digest).hexdigest(inline_script)].pack("H*")].pack("m").chomp
      "'#{digest.to_s.downcase}-#{base64_hashed_content}'"
    end
  end
end
