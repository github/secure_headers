source "https://rubygems.org"

gemspec

group :test do
  gem "tins", "~> 1.6.0" # 1.7 requires ruby 2.0
  gem "pry-nav"
  gem "json", "~> 1"
  gem "rack", "~> 1"
  gem "rspec"
  gem "coveralls"
end

group :guard do
  gem "guard-rspec", platforms: [:ruby_19, :ruby_20, :ruby_21, :ruby_22]
  gem "growl"
  gem "rb-fsevent"
end
