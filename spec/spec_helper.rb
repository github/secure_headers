require 'rubygems'
require 'rspec'

require File.join(File.dirname(__FILE__), '..', 'lib', 'secure_headers')
require 'coveralls'
Coveralls.wear!

include ::SecureHeaders::StrictTransportSecurity::Constants
include ::SecureHeaders::ContentSecurityPolicy::Constants
include ::SecureHeaders::XFrameOptions::Constants
include ::SecureHeaders::XXssProtection::Constants
include ::SecureHeaders::XContentTypeOptions::Constants
include ::SecureHeaders::XDownloadOptions::Constants
