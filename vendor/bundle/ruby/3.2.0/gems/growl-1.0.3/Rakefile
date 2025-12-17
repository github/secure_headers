
$:.unshift 'lib'
require 'growl'
require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new "growl", Growl::VERSION do |p|
  p.author = "TJ Holowaychuk"
  p.email = "tj@vision-media.ca"
  p.summary = "growlnotify bindings"
  p.url = "http://github.com/visionmedia/growl"
  p.runtime_dependencies = []
end

Dir['tasks/**/*.rake'].sort.each { |f| load f }