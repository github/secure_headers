module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, response = @app.call(env)
      [status, headers.merge(SecureHeaders::header_hash(env)), response]
    end
  end
end