# -*- encoding: utf-8 -*-

require File.expand_path('../lib/pry-nav/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = 'pry-nav'
  gem.version       = PryNav::VERSION
  gem.author        = 'Gopal Patel'
  gem.email         = 'nixme@stillhope.com'
  gem.license       = 'MIT'
  gem.homepage      = 'https://github.com/nixme/pry-nav'
  gem.summary       = 'Simple execution navigation for Pry.'
  gem.description   = "Turn Pry into a primitive debugger. Adds 'step' and 'next' commands to control execution."

  gem.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.require_paths = ['lib']

  gem.required_ruby_version = '>= 2.1.0'
  gem.add_runtime_dependency 'pry', '>= 0.9.10', '< 0.15'
  gem.add_development_dependency 'rake'
end
