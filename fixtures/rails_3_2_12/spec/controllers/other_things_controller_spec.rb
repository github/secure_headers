require 'spec_helper'

describe OtherThingsController, :type => :controller do
  describe "headers" do
    it "sets the X-XSS-Protection header" do
      get :index
      expect(response.headers['X-XSS-Protection']).to eq('1; mode=block')
    end

    it "sets the X-Frame-Options header" do
      get :index
      expect(response.headers['X-Frame-Options']).to eq('SAMEORIGIN')
    end

    it "sets the X-WebKit-CSP header" do
      get :index
      expect(response.headers['Content-Security-Policy-Report-Only']).to eq("default-src 'self'; img-src data:; report-uri somewhere;")
    end

    #mock ssl
    it "sets the Strict-Transport-Security header" do
      request.env['HTTPS'] = 'on'
      get :index
      expect(response.headers['Strict-Transport-Security']).to eq("max-age=315576000")
    end

    it "sets the X-Content-Type-Options header" do
      get :index
      expect(response.headers['X-Content-Type-Options']).to eq("nosniff")
    end

    context "using IE" do
      it "sets the X-Content-Type-Options header" do
        request.env['HTTP_USER_AGENT'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
        get :index
        expect(response.headers['X-Content-Type-Options']).to eq("nosniff")
      end
    end
  end
end
