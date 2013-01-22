require 'rubygems'
require 'spork'

unless Spork.using_spork?
  require 'simplecov'
  SimpleCov.start do
    add_filter "spec"
  end
end

Spork.prefork do
  require 'pry'
  require 'rspec'

  # Need these features from Rails, stubbing various features from various versions
  class ApplicationController; end

  module ActionController
    module Routing
      class Routes
        def self.draw; end
      end

      module RouteSet; class Mapper; end; end
    end
  end

  module ActiveSupport
    class JSON
      def self.encode obj, options = nil; end
    end

    module Dependencies
      class << self
        attr_accessor :autoload_paths
        autoload_paths = []
      end
    end
  end

  class Object
    def try(*a, &b); end

    def to_json(options = nil); end
  end

  class NilClass
    def try(*args); end
  end
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

