# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'secure_headers/version'

Gem::Specification.new do |gem|
  gem.name          = "secure_headers"
  gem.version       = SecureHeaders::VERSION
  gem.authors       = ["Neil Matatall"]
  gem.email         = ["neil.matatall@gmail.com"]
  gem.description   = %q{Add easily configured browser headers to responses.}
  gem.summary       = %q{Add easily configured browser headers to responses
    including content security policy, x-frame-options,
    strict-transport-security and more.}
  gem.homepage      = "https://github.com/twitter/secureheaders"
  gem.license       = "Apache Public License 2.0"
  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.add_development_dependency "rake"
end
