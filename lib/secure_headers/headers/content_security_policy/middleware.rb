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

          report_only_config = config.dup
          report_only_config.delete(:experimental)
          report_only_config.delete(:enforce)

          csp_header = ContentSecurityPolicy.new(report_only_config, options)
          headers[csp_header.name] = csp_header.value

          if config[:experimental] && config[:enforce]
            experimental_header = ContentSecurityPolicy.new(config, options)
            headers[experimental_header.name] = experimental_header.value
          end
        end

        [status, headers, response]
      end
    end
  end
end
