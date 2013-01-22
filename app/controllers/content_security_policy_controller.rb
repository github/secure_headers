require 'net/https'
require 'openssl'

class ContentSecurityPolicyController < ActionController::Base
  CA_FILE = File.expand_path(File.join('..','..', '..', 'config', 'curl-ca-bundle.crt'), __FILE__)

  def scribe
    csp = ::SecureHeaders::Configuration.csp

    report_uri = csp[:report_uri] if csp
    if report_uri.nil?
      head :ok
      return
    end

    uri = URI.parse(report_uri)
    http = Net::HTTP.new(uri.host, uri.port)
    if uri.scheme == 'https'
      use_ssl(http)
    end

    request = Net::HTTP::Post.new(uri.to_s)
    request.body = params.to_json

    # fire and forget
    if defined?(Delayed::Job)
      http.delay.request(request)
    else
      http.request(request)
    end

    head :ok
  rescue StandardError => e
    Rails.logger.warn "Unable to POST CSP report to #{report_uri} because #{e}"
    head :bad_request
  end

  def use_ssl request
    request.use_ssl = true
    request.ca_file = CA_FILE
    request.verify_mode = OpenSSL::SSL::VERIFY_PEER
    request.verify_depth = 9
  end
end
