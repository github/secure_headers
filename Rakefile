#!/usr/bin/env rake
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'net/http'
require 'net/https'

desc "Run RSpec"
RSpec::Core::RakeTask.new do |t|
  t.verbose = false
   t.rspec_opts = "--format progress"
end

task :default => :all_spec

desc "Run all specs, and test fixture apps"
task :all_spec => :spec do
  pwd = Dir.pwd

  unless /2\.[2-9]+\.\d+/ =~ RUBY_VERSION
    Dir.chdir 'fixtures/rails_3_2_12'
    puts Dir.pwd
    str = `bundle install >> /dev/null; bundle exec rspec spec`
    puts str
    unless $? == 0
      Dir.chdir pwd
      fail "Header tests with app not using initializer failed exit code: #{$?}"
    end

    Dir.chdir pwd
    Dir.chdir 'fixtures/rails_3_2_12_no_init'
    puts Dir.pwd
    puts `bundle install >> /dev/null; bundle exec rspec spec`

    unless $? == 0
      fail "Header tests with app not using initializer failed"
      Dir.chdir pwd
    end

    Dir.chdir pwd
    Dir.chdir 'fixtures/rails_4_1_8'
    puts Dir.pwd
    puts `bundle install >> /dev/null; bundle exec rspec spec`

    unless $? == 0
      fail "Header tests with Rails 4 failed"
      Dir.chdir pwd
    end
  end
end

begin
  require 'rdoc/task'
rescue LoadError
  require 'rdoc/rdoc'
  require 'rake/rdoctask'
  RDoc::Task = Rake::RDocTask
end

RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'SecureHeaders'
  rdoc.options << '--line-numbers'
  rdoc.rdoc_files.include('lib/**/*.rb')
end
