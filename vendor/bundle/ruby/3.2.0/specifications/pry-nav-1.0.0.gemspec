# -*- encoding: utf-8 -*-
# stub: pry-nav 1.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "pry-nav".freeze
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Gopal Patel".freeze]
  s.date = "2021-11-02"
  s.description = "Turn Pry into a primitive debugger. Adds 'step' and 'next' commands to control execution.".freeze
  s.email = "nixme@stillhope.com".freeze
  s.homepage = "https://github.com/nixme/pry-nav".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1.0".freeze)
  s.rubygems_version = "3.4.20".freeze
  s.summary = "Simple execution navigation for Pry.".freeze

  s.installed_by_version = "3.4.20" if s.respond_to? :installed_by_version

  s.specification_version = 4

  s.add_runtime_dependency(%q<pry>.freeze, [">= 0.9.10", "< 0.15"])
  s.add_development_dependency(%q<rake>.freeze, [">= 0"])
end
