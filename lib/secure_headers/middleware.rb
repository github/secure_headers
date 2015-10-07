module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, response = @app.call(env)
      headers.merge(SecureHeaders::header_hash(env))
      [status, headers, response]
    end
  end
end