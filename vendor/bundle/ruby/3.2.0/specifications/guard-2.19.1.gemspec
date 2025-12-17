# -*- encoding: utf-8 -*-
# stub: guard 2.19.1 ruby lib

Gem::Specification.new do |s|
  s.name = "guard".freeze
  s.version = "2.19.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/guard/guard/releases" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Thibaud Guillaume-Gentil".freeze]
  s.date = "2025-01-02"
  s.description = "Guard is a command line tool to easily handle events on file system modifications.".freeze
  s.email = ["thibaud@thibaud.gg".freeze]
  s.executables = ["guard".freeze, "_guard-core".freeze]
  s.files = ["bin/_guard-core".freeze, "bin/guard".freeze]
  s.homepage = "https://guard.github.io/guard/".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.3".freeze)
  s.rubygems_version = "3.4.20".freeze
  s.summary = "Guard keeps an eye on your file modifications".freeze

  s.installed_by_version = "3.4.20" if s.respond_to? :installed_by_version

  s.specification_version = 4

  s.add_runtime_dependency(%q<formatador>.freeze, [">= 0.2.4"])
  s.add_runtime_dependency(%q<listen>.freeze, [">= 2.7", "< 4.0"])
  s.add_runtime_dependency(%q<logger>.freeze, ["~> 1.6"])
  s.add_runtime_dependency(%q<lumberjack>.freeze, [">= 1.0.12", "< 2.0"])
  s.add_runtime_dependency(%q<nenv>.freeze, ["~> 0.1"])
  s.add_runtime_dependency(%q<notiffany>.freeze, ["~> 0.0"])
  s.add_runtime_dependency(%q<ostruct>.freeze, ["~> 0.6"])
  s.add_runtime_dependency(%q<pry>.freeze, [">= 0.13.0"])
  s.add_runtime_dependency(%q<shellany>.freeze, ["~> 0.0"])
  s.add_runtime_dependency(%q<thor>.freeze, [">= 0.18.1"])
end
