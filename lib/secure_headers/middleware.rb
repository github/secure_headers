module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env.merge(ssl: req.scheme == 'https'))

      headers.merge!(SecureHeaders::header_hash(env))
      [status, headers, response]
    end
  end
end
