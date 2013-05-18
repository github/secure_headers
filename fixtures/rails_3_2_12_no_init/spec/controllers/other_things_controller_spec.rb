require 'spec_helper'

describe OtherThingsController do
  describe "headers" do
    before(:each) do
      # Chrome
      request.env['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5'
    end

    it "sets the X-XSS-Protection header" do
      get :index
      response.headers['X-XSS-Protection'].should == SecureHeaders::XXssProtection::Constants::DEFAULT_VALUE
    end

    it "sets the X-Frame-Options header" do
      get :index
      response.headers['X-Frame-Options'].should == SecureHeaders::XFrameOptions::Constants::DEFAULT_VALUE
    end

    it "sets the X-WebKit-CSP header" do
      get :index
      response.headers['X-WebKit-CSP-Report-Only'].should == "default-src 'self'; img-src data:;"
    end

    #mock ssl
    it "sets the Strict-Transport-Security header" do
      request.env['HTTPS'] = 'on'
      get :index
      response.headers['Strict-Transport-Security'].should == SecureHeaders::StrictTransportSecurity::Constants::DEFAULT_VALUE
    end

    it "sets the X-Content-Type-Options header" do
      get :index
      response.headers['X-Content-Type-Options'].should == SecureHeaders::XContentTypeOptions::Constants::DEFAULT_VALUE
    end

    context "using IE" do
      it "sets the X-Content-Type-Options header" do
        request.env['HTTP_USER_AGENT'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"
        get :index
        response.headers['X-Content-Type-Options'].should == SecureHeaders::XContentTypeOptions::Constants::DEFAULT_VALUE
      end
    end
  end
end
