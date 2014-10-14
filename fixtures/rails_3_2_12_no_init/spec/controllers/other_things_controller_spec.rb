require 'spec_helper'

describe OtherThingsController, :type => :controller do
  include Rack::Test::Methods

  def app
    OtherThingsController.action(:index)
  end

  def request(opts = {})
    options = opts.merge(
      {
        'HTTPS' => 'on',
        'HTTP_USER_AGENT' => "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
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
      expect(@env['X-XSS-Protection']).to eq('1; mode=block')
    end

    it "sets the X-Frame-Options header" do
      get '/'
      expect(@env['X-Frame-Options']).to eq('SAMEORIGIN')
    end

    it "sets the CSP header with a local reference to a nonce" do
      get '/'
      middleware = ::SecureHeaders::ContentSecurityPolicy::Middleware.new(app)
      _, env = middleware.call(request(@env))
      expect(env['Content-Security-Policy-Report-Only']).to match(/default-src 'self'; img-src 'self' data:; script-src 'self' 'nonce-[a-zA-Z0-9\+\/=]{44}' 'unsafe-inline'; report-uri somewhere;/)
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

    context "using IE" do
      it "sets the X-Content-Type-Options header" do
        debugger
        get '/'
        expect(@env['X-Content-Type-Options']).to eq("nosniff")
      end
    end
  end
end
