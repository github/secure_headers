require 'bundler/gem_tasks'
require 'rake/testtask'

task :default => :test

Rake::TestTask.new(:test) do |task|
  task.libs << 'test'
  task.test_files = FileList['test/*_test.rb']
  task.verbose = true
end