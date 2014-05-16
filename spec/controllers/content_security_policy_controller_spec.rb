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

  class FakeRequest
    def user_agent
      "Foo"
    end
    def env
      {"HTTP_X_FORWARDED_FOR" => ""}
    end
    def remote_ip
      "123.12.45.67"
    end
    def content_type
      "application/json"
    end
  end

  describe "#csp" do
    let(:request) { double().as_null_object }
    let(:endpoint) { "https://example.com" }
    let(:secondary_endpoint) { "https://internal.example.com" }

    before(:each) do
      allow(SecureHeaders::Configuration).to receive(:csp).and_return({:report_uri => endpoint, :forward_endpoint => secondary_endpoint})
      expect(subject).to receive :head
      allow(subject).to receive(:params).and_return(params)
      allow(subject).to receive(:request).and_return(FakeRequest.new)
      allow_any_instance_of(Net::HTTP).to receive(:request)
    end

    context "delivery endpoint" do
      it "posts over ssl" do
        expect(subject).to receive(:use_ssl)
        subject.scribe
      end

      it "posts over plain http" do
        allow(SecureHeaders::Configuration).to receive(:csp).and_return(:report_uri => 'http://example.com')
        expect(subject).not_to receive(:use_ssl)
        subject.scribe
      end
    end

    it "makes a POST request" do
      allow(Net::HTTP).to receive(:new).and_return(request)
      expect(request).to receive(:request).with(instance_of(::Net::HTTP::Post))
      allow(params).to receive(:to_json)
      subject.scribe
    end

    it "POSTs to the configured forward_endpoint" do
      expect(Net::HTTP::Post).to receive(:new).with(secondary_endpoint).and_return(request)
      subject.scribe
    end

    it "does not POST if there is no forwarder configured" do
      allow(SecureHeaders::Configuration).to receive(:csp).and_return({})
      expect(Net::HTTP::Post).not_to receive(:new)
      subject.scribe
    end

    it "eliminates known phony CSP reports" do
      allow(SecureHeaders::Configuration).to receive(:csp).and_return(:report_uri => nil)
      expect(Net::HTTP::Post).not_to receive :new
      subject.scribe
    end

    it "logs errors when it cannot forward the CSP report" do
      class Rails; def logger; end; end
      logger = double(:repond_to? => true)
      allow(Rails).to receive(:logger).and_return(logger)

      allow(SecureHeaders::Configuration).to receive(:csp).and_raise(StandardError)

      expect(logger).to receive(:warn)
      subject.scribe
    end
  end
end
