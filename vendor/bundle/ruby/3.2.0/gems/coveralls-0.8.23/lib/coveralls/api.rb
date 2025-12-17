require 'json'
require 'net/https'
require 'tempfile'

module Coveralls
  class API
    if ENV['COVERALLS_ENDPOINT']
      API_HOST = ENV['COVERALLS_ENDPOINT']
      API_DOMAIN = ENV['COVERALLS_ENDPOINT']
    else
      API_HOST = ENV['COVERALLS_DEVELOPMENT'] ? "localhost:3000" : "coveralls.io"
      API_PROTOCOL = ENV['COVERALLS_DEVELOPMENT'] ? "http" : "https"
      API_DOMAIN = "#{API_PROTOCOL}://#{API_HOST}"
    end

    API_BASE = "#{API_DOMAIN}/api/v1"

    def self.post_json(endpoint, hash)
      disable_net_blockers!

      uri = endpoint_to_uri(endpoint)

      Coveralls::Output.puts("#{ JSON.pretty_generate(hash) }", :color => "green") if ENV['COVERALLS_DEBUG']
      Coveralls::Output.puts("[Coveralls] Submitting to #{API_BASE}", :color => "cyan")

      client  = build_client(uri)
      request = build_request(uri.path, hash)

      response = client.request(request)

      response_hash = JSON.load(response.body.to_str)

      if response_hash['message']
        Coveralls::Output.puts("[Coveralls] #{ response_hash['message'] }", :color => "cyan")
      end

      if response_hash['url']
        Coveralls::Output.puts("[Coveralls] #{ Coveralls::Output.format(response_hash['url'], :color => "underline") }", :color => "cyan")
      end

      case response
      when Net::HTTPServiceUnavailable
        Coveralls::Output.puts("[Coveralls] API timeout occured, but data should still be processed", :color => "red")
      when Net::HTTPInternalServerError
        Coveralls::Output.puts("[Coveralls] API internal error occured, we're on it!", :color => "red")
      end
    end

    private

    def self.disable_net_blockers!
      begin
        require 'webmock'

        allow = WebMock::Config.instance.allow || []
        WebMock::Config.instance.allow = [*allow].push API_HOST
      rescue LoadError
      end

      begin
        require 'vcr'

        VCR.send(VCR.version.major < 2 ? :config : :configure) do |c|
          c.ignore_hosts API_HOST
        end
      rescue LoadError
      end
    end

    def self.endpoint_to_uri(endpoint)
      URI.parse("#{API_BASE}/#{endpoint}")
    end

    def self.build_client(uri)
      client = Net::HTTP.new(uri.host, uri.port)
      client.use_ssl = true if uri.port == 443
      client.verify_mode = OpenSSL::SSL::VERIFY_NONE

      unless client.respond_to?(:ssl_version=)
        Net::HTTP.ssl_context_accessor("ssl_version")
      end

      client.ssl_version = 'TLSv1'

      client
    end

    def self.build_request(path, hash)
      request  = Net::HTTP::Post.new(path)
      boundary = rand(1_000_000).to_s

      request.body         = build_request_body(hash, boundary)
      request.content_type = "multipart/form-data, boundary=#{boundary}"

      request
    end

    def self.build_request_body(hash, boundary)
      hash = apified_hash(hash)
      file = hash_to_file(hash)

      "--#{boundary}\r\n" \
      "Content-Disposition: form-data; name=\"json_file\"; filename=\"#{File.basename(file.path)}\"\r\n" \
      "Content-Type: text/plain\r\n\r\n" +
      File.read(file.path) +
      "\r\n--#{boundary}--\r\n"
    end

    def self.hash_to_file(hash)
      file = nil
      Tempfile.open(['coveralls-upload', 'json']) do |f|
        f.write(JSON.dump hash)
        file = f
      end
      File.new(file.path, 'rb')
    end

    def self.apified_hash hash
      config = Coveralls::Configuration.configuration
      if ENV['COVERALLS_DEBUG'] || Coveralls.testing
        Coveralls::Output.puts "[Coveralls] Submitting with config:", :color => "yellow"
        output = JSON.pretty_generate(config).gsub(/"repo_token": ?"(.*?)"/,'"repo_token": "[secure]"')
        Coveralls::Output.puts output, :color => "yellow"
      end
      hash.merge(config)
    end
  end
end
