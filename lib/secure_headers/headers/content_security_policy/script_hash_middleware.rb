module SecureHeaders
  class ContentSecurityPolicy
    class ScriptHashMiddleware
      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, response = @app.call(env)
        metadata = env[ContentSecurityPolicy::ENV_KEY]
        if !metadata.nil?
          config, options = metadata.values_at(:config, :options)
          config.merge!(:script_hashes => env[HASHES_ENV_KEY])
          csp_header = ContentSecurityPolicy.new(config, options)
          headers[csp_header.name] = csp_header.value
        end

        [status, headers, response]
      end
    end
  end
end
