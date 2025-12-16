# -*- encoding: utf-8 -*-
# stub: coveralls 0.8.23 ruby lib

Gem::Specification.new do |s|
  s.name = "coveralls".freeze
  s.version = "0.8.23"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Nick Merwin".freeze, "Wil Gieseler".freeze]
  s.date = "2019-05-01"
  s.description = "A Ruby implementation of the Coveralls API.".freeze
  s.email = ["nick@lemurheavy.com".freeze, "supapuerco@gmail.com".freeze]
  s.executables = ["coveralls".freeze]
  s.files = ["bin/coveralls".freeze]
  s.homepage = "https://coveralls.io".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7".freeze)
  s.rubygems_version = "3.4.20".freeze
  s.summary = "A Ruby implementation of the Coveralls API.".freeze

  s.installed_by_version = "3.4.20" if s.respond_to? :installed_by_version

  s.specification_version = 4

  s.add_runtime_dependency(%q<json>.freeze, [">= 1.8", "< 3"])
  s.add_runtime_dependency(%q<simplecov>.freeze, ["~> 0.16.1"])
  s.add_runtime_dependency(%q<tins>.freeze, ["~> 1.6"])
  s.add_runtime_dependency(%q<term-ansicolor>.freeze, ["~> 1.3"])
  s.add_runtime_dependency(%q<thor>.freeze, [">= 0.19.4", "< 2.0"])
  s.add_development_dependency(%q<bundler>.freeze, ["~> 2.0"])
end
