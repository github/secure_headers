module SecureHeaders
  class ContentSecurityPolicy
    class Middleware
      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, response = @app.call(env)
        metadata = env[ContentSecurityPolicy::ENV_KEY]

        if !metadata.nil?
          config, options = metadata.values_at(:config, :options)

          csp_header = ContentSecurityPolicy.new(config, options)
          headers[csp_header.name] = csp_header.value

          if config[:experimental] && config[:enforce]
            experimental_header = ContentSecurityPolicy.new(config, options.merge(:experimental => true))
            headers[experimental_header.name] = experimental_header.value
          end
        end

        [status, headers, response]
      end
    end
  end
end
