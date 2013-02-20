guard 'spork', :aggressive_kill => false do
  watch('spec/spec_helper.rb') { :rspec }
end

guard 'rspec', :cli => "--color --drb --debug", :keep_failed => true, :all_after_pass => true, :focus_on_failed => true do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^lib/(.+)\.rb$})     { |m| "spec/lib/#{m[1]}_spec.rb" }
  watch(%r{^app/controllers/(.+)\.rb$})     { |m| "spec/controllers/#{m[1]}_spec.rb" }
  watch('spec/spec_helper.rb')  { "spec" }
end