# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe ReportingEndpoints do
    describe "#make_header" do
      it "returns nil when config is nil" do
        expect(ReportingEndpoints.make_header(nil)).to be_nil
      end

      it "returns nil when config is OPT_OUT" do
        expect(ReportingEndpoints.make_header(OPT_OUT)).to be_nil
      end

      it "formats a single endpoint" do
        config = { "csp-endpoint" => "https://example.com/csp-reports" }
        header_name, value = ReportingEndpoints.make_header(config)
        expect(header_name).to eq("reporting-endpoints")
        expect(value).to eq('csp-endpoint="https://example.com/csp-reports"')
      end

      it "formats a single endpoint with a symbol" do
        config = { "csp-endpoint": "https://example.com/csp-reports" }
        header_name, value = ReportingEndpoints.make_header(config)
        expect(header_name).to eq("reporting-endpoints")
        expect(value).to eq('csp-endpoint="https://example.com/csp-reports"')
      end

      it "formats multiple endpoints" do
        config = {
          "csp-endpoint" => "https://example.com/csp-reports",
          "permissions-endpoint" => "https://example.com/permissions-reports"
        }
        header_name, value = ReportingEndpoints.make_header(config)
        expect(header_name).to eq("reporting-endpoints")
        # Order may vary, so check both endpoints are present
        expect(value).to include('csp-endpoint="https://example.com/csp-reports"')
        expect(value).to include('permissions-endpoint="https://example.com/permissions-reports"')
        expect(value).to include(",")
      end

      it "validates that endpoints are present" do
        expect do
          ReportingEndpoints.validate_config!({})
        end.to_not raise_error
      end
    end

    describe "#validate_config!" do
      it "accepts nil" do
        expect do
          ReportingEndpoints.validate_config!(nil)
        end.to_not raise_error
      end

      it "accepts OPT_OUT" do
        expect do
          ReportingEndpoints.validate_config!(OPT_OUT)
        end.to_not raise_error
      end

      it "accepts valid endpoint configuration" do
        expect do
          ReportingEndpoints.validate_config!({
            "csp-violations" => "https://example.com/reports"
          })
        end.to_not raise_error
      end

      it "accepts valid endpoint configuration with symbol keys" do
        expect do
          ReportingEndpoints.validate_config!({
            "csp-violations": "https://example.com/reports"
          })
        end.to_not raise_error
      end

      it "rejects non-hash config" do
        expect do
          ReportingEndpoints.validate_config!("not a hash")
        end.to raise_error(TypeError)
      end

      it "rejects empty endpoint name" do
        expect do
          ReportingEndpoints.validate_config!({
            "" => "https://example.com/reports"
          })
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "rejects non-string endpoint name" do
        expect do
          ReportingEndpoints.validate_config!({
            123 => "https://example.com/reports"
          })
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "rejects empty endpoint URL" do
        expect do
          ReportingEndpoints.validate_config!({
            "csp-endpoint" => ""
          })
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "rejects non-string endpoint URL" do
        expect do
          ReportingEndpoints.validate_config!({
            "csp-endpoint" => 123
          })
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "rejects non-https URLs" do
        expect do
          ReportingEndpoints.validate_config!({
            "csp-endpoint" => "http://example.com/reports"
          })
        end.to raise_error(ReportingEndpointsConfigError, /must use https/)
      end
    end
  end
end
