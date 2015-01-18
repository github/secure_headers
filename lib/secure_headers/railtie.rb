# rails 3.1+
if defined?(Rails::Railtie)
  module SecureHeaders
    class Railtie < Rails::Engine
      isolate_namespace ::SecureHeaders if defined? isolate_namespace # rails 3.0
      conflicting_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options']
      initializer "secure_headers.action_controller" do
        ActiveSupport.on_load(:action_controller) do
          include ::SecureHeaders

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
      include ::SecureHeaders
    end
  end
end
