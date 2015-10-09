module SecureHeaders
  class Middleware
    def initialize(app)
      @app = app
    end

    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)
      if headers["Content-Type"] && headers["Content-Type"].include?("text/html")
        headers.merge!(SecureHeaders::header_hash(env.merge(ssl: req.scheme == 'https')))
      end
      [status, headers, response]
    ensure
      puts "Ensure"
      puts Thread.current
      puts SecureHeaders::request_config
      SecureHeaders::request_config = nil
      puts SecureHeaders::request_config
    end
  end
end
