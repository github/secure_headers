# frozen_string_literal: true
source "https://rubygems.org"

gemspec

group :test do
  gem "coveralls"
  gem "json", "~> 1"
  gem "pry-nav"
  gem "rack", "~> 1"
  gem "rspec"
  gem "rubocop", "~> 0.47.0"
  gem "rubocop-github"
  gem "term-ansicolor", "< 1.4"
  gem "tins", "~> 1.6.0" # 1.7 requires ruby 2.0
end

group :guard do
  gem "growl"
  gem "guard-rspec", platforms: [:ruby_19, :ruby_20, :ruby_21, :ruby_22]
  gem "rb-fsevent"
end
