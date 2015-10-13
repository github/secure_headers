module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)
      headers.merge!(SecureHeaders::header_hash(env.merge(ssl: req.scheme == 'https')))
      [status, headers, response]
    ensure
      SecureHeaders::secure_headers_request_config = nil
    end
  end
end
