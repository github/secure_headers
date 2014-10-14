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

      initializer "secure_headers.add_middleware" do |app|
        app.middleware.use SecureHeaders::ContentSecurityPolicy::Middleware
      end
    end
  end
else
  module ActionController
    class Base
      include ::SecureHeaders
    end
  end

  module SecureHeaders
    module Routing
      module MapperExtensions
        def csp_endpoint
          @set.add_route(ContentSecurityPolicy::FF_CSP_ENDPOINT, {:controller => "content_security_policy", :action => "scribe"})
        end
      end
    end
  end

  if defined?(ActiveSupport::Dependencies)
    if ActiveSupport::Dependencies.autoload_paths
      ActiveSupport::Dependencies.autoload_paths << File.expand_path(File.join("..", "..", "..", "app", "controllers"), __FILE__)
    else
      ActiveSupport::Dependencies.autoload_paths = [File.expand_path(File.join("..", "..", "..", "app", "controllers"), __FILE__)]
    end
  end

  if defined? ActionController::Routing
    ActionController::Routing::RouteSet::Mapper.send :include, ::SecureHeaders::Routing::MapperExtensions
  end
end
