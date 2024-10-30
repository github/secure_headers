# frozen_string_literal: true
# rails 3.1+
if defined?(Rails::Railtie)
  module SecureHeaders
    class Railtie < Rails::Railtie
      isolate_namespace SecureHeaders if defined? isolate_namespace # rails 3.0
      conflicting_headers = ["X-Frame-Options", "X-XSS-Protection",
                             "x-permitted-cross-domain-policies", "x-download-options",
                             "X-Content-Type-Options", "strict-transport-security",
                             "content-security-policy", "content-security-policy-report-only",
                             "Public-Key-Pins", "Public-Key-Pins-Report-Only", "referrer-policy"]

      initializer "secure_headers.middleware" do
        Rails.application.config.middleware.insert_before 0, SecureHeaders::Middleware
      end

      rake_tasks do
        load File.expand_path(File.join("..", "..", "lib", "tasks", "tasks.rake"), File.dirname(__FILE__))
      end

      initializer "secure_headers.action_controller" do
        ActiveSupport.on_load(:action_controller) do
          include SecureHeaders

          unless Rails.application.config.action_dispatch.default_headers.nil?
            conflicting_headers.each do |header|
              Rails.application.config.action_dispatch.default_headers.delete(header)
            end
          end
        end
      end
    end
  end
else
  module ActionController
    class Base
      include SecureHeaders
    end
  end
end
