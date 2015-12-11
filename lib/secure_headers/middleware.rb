module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end
  end
end
