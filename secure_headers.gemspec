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
  gem.metadata      = {
    "bug_tracker_uri"   => "https://github.com/github/secure_headers/issues",
    "changelog_uri"     => "https://github.com/github/secure_headers/blob/master/CHANGELOG.md",
    "documentation_uri" => "https://rubydoc.info/gems/secure_headers",
    "homepage_uri"      => gem.homepage,
    "source_code_uri"   => "https://github.com/github/secure_headers",
    "rubygems_mfa_required" => "true",
  }
  gem.license       = "MIT"

  gem.files         = Dir["bin/**/*", "lib/**/*", "README.md", "CHANGELOG.md", "LICENSE", "Gemfile", "secure_headers.gemspec"]
  gem.require_paths = ["lib"]

  gem.extra_rdoc_files = Dir["README.md", "CHANGELOG.md", "LICENSE"]

  gem.add_dependency "cgi", ">= 0.1"

  gem.add_development_dependency "rake"
end
