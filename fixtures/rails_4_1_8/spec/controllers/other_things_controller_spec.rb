require 'spec_helper'

require 'secure_headers/headers/content_security_policy/script_hash_middleware'

describe OtherThingsController, :type => :controller do
  include Rack::Test::Methods

  def app
    OtherThingsController.action(:index)
  end

  def request(opts = {})
    options = opts.merge(
      {
        'HTTPS' => 'on',
        'HTTP_USER_AGENT' => "Mozilla/5.0 (Macintosh; Intel Mac OS X 1084) AppleWebKit/537.22 (KHTML like Gecko) Chrome/25.0.1364.99 Safari/537.22"
      }
    )


    Rack::MockRequest.env_for('/', options)
  end


  describe "headers" do
    before(:each) do
      _, @env = app.call(request)
    end

    it "sets the X-XSS-Protection header" do
      get '/'
      expect(@env['X-XSS-Protection']).to eq('0')
    end

    it "sets the X-Frame-Options header" do
      get '/'
      expect(@env['X-Frame-Options']).to eq('DENY')
    end

    it "sets the CSP header with a local reference to a nonce" do
      middleware = ::SecureHeaders::ContentSecurityPolicy::ScriptHashMiddleware.new(app)
      _, env = middleware.call(request(@env))
      expect(env['Content-Security-Policy-Report-Only']).to match(/script-src[^;]*'nonce-[a-zA-Z0-9\+\/=]{44}'/)
    end

    it "sets the required hashes to whitelist inline script" do
      middleware = ::SecureHeaders::ContentSecurityPolicy::ScriptHashMiddleware.new(app)
      _, env = middleware.call(request(@env))
      hashes = ['sha256-VjDxT7saxd2FgaUQQTWw/jsTnvonaoCP/ACWDBTpyhU=', 'sha256-ZXAcP8a0y1pPMTJW8pUr43c+XBkgYQBwHOPvXk9mq5A=']
      hashes.each do |hash|
        expect(env['Content-Security-Policy-Report-Only']).to include(hash)
      end
    end

    it "sets the Strict-Transport-Security header" do
      get '/'
      expect(@env['Strict-Transport-Security']).to eq("max-age=315576000")
    end

    it "sets the X-Download-Options header" do
      get '/'
      expect(@env['X-Download-Options']).to eq('noopen')
    end

    it "sets the X-Content-Type-Options header" do
      get '/'
      expect(@env['X-Content-Type-Options']).to eq("nosniff")
    end

    it "sets the X-Permitted-Cross-Domain-Policies" do
      get '/'
      expect(@env['X-Permitted-Cross-Domain-Policies']).to eq("none")
    end

    context "using IE" do
      it "sets the X-Content-Type-Options header" do
        @env['HTTP_USER_AGENT'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
        get '/'
        expect(@env['X-Content-Type-Options']).to eq("nosniff")
      end
    end
  end
end
