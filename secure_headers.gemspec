# -*- encoding: utf-8 -*-
Gem::Specification.new do |gem|
  gem.name          = "secure_headers"
  gem.version       = "3.7.1"
  gem.authors       = ["Neil Matatall"]
  gem.email         = ["neil.matatall@gmail.com"]
  gem.description   = 'Manages application of security headers with many safe defaults.'
  gem.summary       = 'Add easily configured security headers to responses
    including content-security-policy, x-frame-options,
    strict-transport-security, etc.'
  gem.homepage      = "https://github.com/twitter/secureheaders"
  gem.license       = "Apache Public License 2.0"
  gem.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.add_development_dependency "rake"
  gem.add_dependency "useragent"
end
