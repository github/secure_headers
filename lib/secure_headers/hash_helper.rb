module SecureHeaders
  module HashHelper
    def hash_source(inline_script, digest = :SHA256)
      ["'", [digest.to_s.downcase, "-", [[Digest.const_get(digest).hexdigest(inline_script)].pack("H*")].pack("m").chomp].join, "'"].join
    end
  end
end
