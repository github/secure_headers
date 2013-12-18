require 'net/https'
require 'openssl'

class ContentSecurityPolicyController < ActionController::Base
  CA_FILE = File.expand_path(File.join('..','..', '..', 'config', 'curl-ca-bundle.crt'), __FILE__)

  def scribe
    csp = ::SecureHeaders::Configuration.csp || {}

    forward_endpoint = csp[:forward_endpoint]
    if forward_endpoint
      forward_params_to(forward_endpoint)
    end

    head :ok
  rescue StandardError => e
    log_warning(forward_endpoint, e)
    head :bad_request
  end

  private

  def forward_params_to(forward_endpoint)
    uri = URI.parse(forward_endpoint)
    http = Net::HTTP.new(uri.host, uri.port)
    if uri.scheme == 'https'
      use_ssl(http)
    end

    if request.content_type == "application/csp-report"
      request.body.rewind
      params.merge!(ActiveSupport::JSON.decode(request.body.read))
    end

    ua = request.user_agent
    xff = forwarded_for

    request = Net::HTTP::Post.new(uri.to_s)
    request.initialize_http_header({
      'User-Agent' => ua,
      'X-Forwarded-For' => xff,
      'Content-Type' => 'application/json',
    })
    request.body = params.to_json

    # fire and forget
    if defined?(Delayed::Job)
      http.delay.request(request)
    else
      http.request(request)
    end
  end

  def forwarded_for
    req_xff = request.env["HTTP_X_FORWARDED_FOR"]
    if req_xff && req_xff != ""
      "#{req_xff}, #{request.remote_ip}"
    else
      request.remote_ip
    end
  end

  def use_ssl request
    request.use_ssl = true
    request.ca_file = CA_FILE
    request.verify_mode = OpenSSL::SSL::VERIFY_PEER
    request.verify_depth = 9
  end

  def log_warning(forward_endpoint, e)
    if defined?(Rails.logger)
      Rails.logger.warn("Unable to POST CSP report to #{forward_endpoint} because #{e}")
    end
  end
end
