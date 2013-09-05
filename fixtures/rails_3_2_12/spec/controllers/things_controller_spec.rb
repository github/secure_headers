require 'spec_helper'

# This controller is meant to be something that inherits config from application controller
# all values are defaulted because no initializer is configured, and the values in app controller
# only provide csp => false

describe ThingsController do
  describe "headers" do
    before(:each) do
      # Chrome 19
      request.env['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5'
      request.env['HTTPS'] = 'on'
    end

    it "doesn't set some headers for API requests" do
      get :index, :format => :json
      response.headers['X-XSS-Protection'].should == nil
      response.headers['X-WebKit-CSP'].should == nil
      response.headers['X-Content-Type-Options'].should == nil
      response.headers['X-WebKit-CSP-Report-Only'].should == nil
      response.headers['X-Content-Security-Policy'].should == nil
      response.headers['X-Content-Security-Policy-Report-Only'].should == nil
      response.headers['Strict-Transport-Security'].should == "max-age=315576000"
    end

    it "only sets hsts for xhr requests" do
      get :index, :format => :json
      response.headers['X-XSS-Protection'].should == nil
      response.headers['X-WebKit-CSP'].should == nil
      response.headers['X-Content-Type-Options'].should == nil
      response.headers['X-WebKit-CSP-Report-Only'].should == nil
      response.headers['X-Content-Security-Policy'].should == nil
      response.headers['X-Content-Security-Policy-Report-Only'].should == nil
      response.headers['Strict-Transport-Security'].should == "max-age=315576000"
    end

    it "sets the X-XSS-Protection header" do
      get :index
      response.headers['X-XSS-Protection'].should == '1; mode=block'
    end

    it "sets the X-Frame-Options header" do
      get :index
      response.headers['X-Frame-Options'].should == 'SAMEORIGIN'
    end

    it "sets the X-WebKit-CSP header" do
      get :index
      response.headers['X-WebKit-CSP-Report-Only'].should == nil
    end

    #mock ssl
    it "sets the Strict-Transport-Security header" do
      request.env['HTTPS'] = 'on'
      get :index
      response.headers['Strict-Transport-Security'].should == "max-age=315576000"
    end

    it "sets the X-Content-Type-Options header" do
      get :index
      response.headers['X-Content-Type-Options'].should == "nosniff"
    end

    context "using IE" do
      it "sets the X-Content-Type-Options header" do
        request.env['HTTP_USER_AGENT'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
        get :index
        response.headers['X-Content-Type-Options'].should == "nosniff"
      end
    end
  end
end


# response.headers['X-WebKit-CSP-Report-Only'].should == "default-src 'self'; report-uri somewhere"
