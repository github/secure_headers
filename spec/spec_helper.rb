require 'rubygems'
require 'rspec'

require File.join(File.dirname(__FILE__), '..', 'lib', 'secure_headers')

if defined?(Coveralls)
  Coveralls.wear!
end

include ::SecureHeaders::StrictTransportSecurity::Constants
include ::SecureHeaders::ContentSecurityPolicy::Constants
include ::SecureHeaders::XFrameOptions::Constants
include ::SecureHeaders::XXssProtection::Constants
include ::SecureHeaders::XContentTypeOptions::Constants
include ::SecureHeaders::XDownloadOptions::Constants

USER_AGENTS = {
  :firefox => 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:14.0) Gecko/20100101 Firefox/14.0.1',
  :chrome => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5',
  :ie => 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)',
  :opera => 'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
  :ios5 => "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
  :ios6 => "Mozilla/5.0 (iPhone; CPU iPhone OS 614 like Mac OS X) AppleWebKit/536.26 (KHTML like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25",
  :safari5 => "Mozilla/5.0 (iPad; CPU OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko ) Version/5.1 Mobile/9B176 Safari/7534.48.3",
  :safari5_1 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10",
  :safari6 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/536.30.1 (KHTML like Gecko) Version/6.0.5 Safari/536.30.1"
}

def should_assign_header name, value
  expect(response.headers).to receive(:[]=).with(name, value)
end

def should_not_assign_header name
  expect(response.headers).not_to receive(:[]=).with(name, anything)
end
