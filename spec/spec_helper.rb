require 'rubygems'
require 'spork'

unless Spork.using_spork?
  require 'simplecov'
  SimpleCov.start do
    add_filter "spec"
  end
end

Spork.prefork do
  require 'rspec'
end

Spork.each_run do
  require File.join(File.dirname(__FILE__), '..', 'lib', 'secure_headers')
  require File.join(File.dirname(__FILE__), '..', 'app', 'controllers', 'content_security_policy_controller')
  include ::SecureHeaders::StrictTransportSecurity::Constants
  include ::SecureHeaders::ContentSecurityPolicy::Constants
  include ::SecureHeaders::XFrameOptions::Constants
  include ::SecureHeaders::XXssProtection::Constants
  include ::SecureHeaders::XContentTypeOptions::Constants
end

