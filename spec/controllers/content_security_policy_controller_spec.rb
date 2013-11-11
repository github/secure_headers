require 'spec_helper'

describe ContentSecurityPolicyController do
  let(:params) {
    {
      "csp-report" => {
        "document-uri" => "http://localhost:3001/csp","violated-directive" => "script-src 'none'",
        "original-policy" => "default-src https://* 'unsafe-eval'; frame-src 'self'; img-src https://*; report-uri http://localhost:3001/scribes/csp_report; script-src 'none'; style-src 'unsafe-inline' 'self';",
        "blocked-uri" => "http://localhost:3001/stuff.js"
      }
    }
  }

  describe "#csp" do
    let(:request) { double().as_null_object }
    let(:endpoint) { "https://example.com" }
    let(:secondary_endpoint) { "https://internal.example.com" }

    before(:each) do
      SecureHeaders::Configuration.stub(:csp).and_return({:report_uri => endpoint, :forward_endpoint => secondary_endpoint})
      subject.should_receive :head
      subject.stub(:params).and_return(params)
      Net::HTTP.any_instance.stub(:request)
    end

    context "delivery endpoint" do
      it "posts over ssl" do
        subject.should_receive(:use_ssl)
        subject.scribe
      end

      it "posts over plain http" do
        SecureHeaders::Configuration.stub(:csp).and_return(:report_uri => 'http://example.com')
        subject.should_not_receive(:use_ssl)
        subject.scribe
      end
    end

    it "makes a POST request" do
      Net::HTTP.stub(:new).and_return(request)
      request.should_receive(:request).with(instance_of(::Net::HTTP::Post))
      params.stub(:to_json)
      subject.scribe
    end

    it "POSTs to the configured forward_endpoint" do
      Net::HTTP::Post.should_receive(:new).with(secondary_endpoint).and_return(request)
      subject.scribe
    end

    it "does not POST if there is no forwarder configured" do
      SecureHeaders::Configuration.stub(:csp).and_return({})
      Net::HTTP::Post.should_not_receive(:new)
      subject.scribe
    end

    it "eliminates known phony CSP reports" do
      SecureHeaders::Configuration.stub(:csp).and_return(:report_uri => nil)
      Net::HTTP::Post.should_not_receive :new
      subject.scribe
    end

    it "logs errors when it cannot forward the CSP report" do
      class Rails; def logger; end; end
      logger = double(:repond_to? => true)
      Rails.stub(:logger).and_return(logger)

      SecureHeaders::Configuration.stub(:csp).and_raise(StandardError)

      logger.should_receive(:warn)
      subject.scribe
    end
  end
end
