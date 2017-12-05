# -*- encoding: utf-8 -*-
# frozen_string_literal: true
Gem::Specification.new do |gem|
  gem.name          = "secure_headers"
  gem.version       = "5.0.4"
  gem.authors       = ["Neil Matatall"]
  gem.email         = ["neil.matatall@gmail.com"]
  gem.description   = "Manages application of security headers with many safe defaults."
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
  gem.add_dependency "useragent", ">= 0.15.0"

  # TODO: delete this after 4.1 is cut or a number of 4.0.x releases have occurred
  gem.post_install_message = <<-POST_INSTALL

**********
:wave: secure_headers 5.0 introduces a lot of breaking changes (in the name of security!). It's highly likely you will need to update your secure_headers cookie configuration to avoid breaking things. See the upgrade guide for details: https://github.com/twitter/secureheaders/blob/master/docs/upgrading-to-5-0.md
**********

  POST_INSTALL
end
