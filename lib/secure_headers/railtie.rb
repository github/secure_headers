# rails 3.1+
if defined?(Rails::Railtie)
  module SecureHeaders
    class Railtie < Rails::Engine
      isolate_namespace ::SecureHeaders if defined? isolate_namespace # rails 3.0
      initializer "secure_headers.action_controller" do
        ActiveSupport.on_load(:action_controller) do
          include ::SecureHeaders
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
