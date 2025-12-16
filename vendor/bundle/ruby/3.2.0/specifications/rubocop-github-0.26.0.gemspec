# -*- encoding: utf-8 -*-
# stub: rubocop-github 0.26.0 ruby lib

Gem::Specification.new do |s|
  s.name = "rubocop-github".freeze
  s.version = "0.26.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/github/rubocop-github/issues", "documentation_uri" => "https://github.com/github/rubocop-github", "source_code_uri" => "https://github.com/github/rubocop-github" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["GitHub".freeze]
  s.date = "2025-06-09"
  s.description = "Code style checking for GitHub Ruby repositories".freeze
  s.email = "engineering@github.com".freeze
  s.homepage = "https://github.com/github/rubocop-github".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1.0".freeze)
  s.rubygems_version = "3.4.20".freeze
  s.summary = "RuboCop GitHub".freeze

  s.installed_by_version = "3.4.20" if s.respond_to? :installed_by_version

  s.specification_version = 4

  s.add_runtime_dependency(%q<rubocop>.freeze, [">= 1.76"])
  s.add_runtime_dependency(%q<rubocop-performance>.freeze, [">= 1.24"])
  s.add_runtime_dependency(%q<rubocop-rails>.freeze, [">= 2.23"])
  s.add_development_dependency(%q<actionview>.freeze, ["~> 7.2.2.1"])
  s.add_development_dependency(%q<minitest>.freeze, [">= 0"])
  s.add_development_dependency(%q<rake>.freeze, [">= 0"])
end
