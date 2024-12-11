# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "secure_headers/version"

Gem::Specification.new do |gem|
  gem.name          = "secure_headers"
  gem.version       = SecureHeaders::VERSION
  gem.authors       = ["Neil Matatall"]
  gem.email         = ["neil.matatall@gmail.com"]
  gem.summary       = "Manages application of security headers with many safe defaults."
  gem.description   = 'Add easily configured security headers to responses
    including content-security-policy, x-frame-options,
    strict-transport-security, etc.'
  gem.homepage      = "https://github.com/github/secure_headers"
  gem.license       = "MIT"
  gem.files         = Dir["bin/**/*", "lib/**/*", "spec/**/*"] + ["README.md", "Gemfile", "Guardfile", "Rakefile", ".rspec", ".rubocop.yml", "secure_headers.gemspec"]
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.add_development_dependency "rake"
end
