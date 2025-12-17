source 'https://rubygems.org'

# Specify your gem's dependencies in coveralls-ruby.gemspec
gemspec

gem 'rake', Gem::Version.new(RUBY_VERSION) < Gem::Version.new('1.9.3') ? '~> 10.3' : '>= 10.3'
gem 'rspec', '>= 3.2'
gem 'simplecov', :require => false
gem 'truthy', '>= 1'

if Gem::Version.new(RUBY_VERSION) < Gem::Version.new('1.9')
  gem 'vcr', '~> 2.9'
  gem 'webmock', '~> 1.20'
else
  gem 'vcr', '>= 2.9'
  gem 'webmock', '>= 1.20'
end

platforms :ruby_18 do
  gem 'addressable', '~> 2.3.8', :group => :test
  gem 'mime-types', '~> 1.25'
end

platforms :ruby_18, :ruby_19 do
  gem 'json', '~> 1.8'
  gem 'term-ansicolor', '~> 1.3.0'
  gem 'tins', '~> 1.6.0'
end

platforms :jruby do
  gem 'jruby-openssl'
end

platform :rbx do
  gem 'rubysl', '~> 2.0'
  gem 'rubinius-developer_tools'
end

group :test do
  gem 'pry'
end
