require 'spec_helper'

# This controller is meant to be something that inherits config from application controller
# all values are defaulted because no initializer is configured, and the values in app controller
# only provide csp => false

describe ThingsController do
  describe "headers" do
    before(:each) do
        # Chrome
        request.env['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5'
    end

    it "sets the X-XSS-PROTECTION header" do
      get :index
      response.headers['X-XSS-Protection'].should == '1; mode=BLOCK'
    end

    it "sets the X-FRAME-OPTIONS header" do
      get :index
      response.headers['X-FRAME-OPTIONS'].should == 'SAMEORIGIN'
    end

    it "sets the X-WebKit-CSP header" do
      get :index
      response.headers['X-WebKit-CSP-Report-Only'].should == nil
    end

    #mock ssl
    it "sets the STRICT-TRANSPORT-SECURITY header" do
      request.env['HTTPS'] = 'on'
      get :index
      response.headers['Strict-Transport-Security'].should == "max-age=315576000"
    end

    context "using IE" do
      it "sets the X-CONTENT-TYPE-OPTIONS header" do
        request.env['HTTP_USER_AGENT'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
        get :index
        response.headers['X-Content-Type-Options'].should == "nosniff"
      end
    end
  end
end


# response.headers['X-WebKit-CSP-Report-Only'].should == "default-src 'self'; report-uri somewhere"