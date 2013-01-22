guard 'spork', :rspec_env => { 'RAILS_ENV' => 'test' } do
  watch('spec/spec_helper.rb') { :rspec }
end

guard 'rspec', :cli => "--color --drb", :keep_failed => true, :all_after_pass => true do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^lib/(.+)\.rb$})     { |m| "spec/lib/#{m[1]}_spec.rb" }
  watch(%r{^app/controllers/(.+)\.rb$})     { |m| "spec/controllers/#{m[1]}_spec.rb" }
  watch('spec/spec_helper.rb')  { "spec" }
end