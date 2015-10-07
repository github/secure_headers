module SecureHeaders
  class Middlware
    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, response = @app.call(env)
      headers.merge(SecureHeaders::header_hash(:ua => env["HTTP_USER_AGENT"]))
      [status, headers, response]
    end
  end
end