# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe ReportingEndpoints do
    specify { expect(ReportingEndpoints.new(default: "https://example.com/reports").value).to eq('default="https://example.com/reports"') }
    specify do
      config = { default: "https://example.com/reports", csp: "https://example.com/csp" }
      header_value = 'default="https://example.com/reports", csp="https://example.com/csp"'
      expect(ReportingEndpoints.new(config).value).to eq(header_value)
    end
    specify do
      config = { endpoint1: "https://example.com/1", endpoint2: "https://example.com/2", endpoint3: "https://example.com/3" }
      header_value = 'endpoint1="https://example.com/1", endpoint2="https://example.com/2", endpoint3="https://example.com/3"'
      expect(ReportingEndpoints.new(config).value).to eq(header_value)
    end

    context "with an invalid configuration" do
      it "raises an exception when configuration isn't a hash" do
        expect do
          ReportingEndpoints.validate_config!(%w(a))
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "raises an exception when configuration is a string" do
        expect do
          ReportingEndpoints.validate_config!("https://example.com")
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "raises an exception when endpoint name is not a string or symbol" do
        expect do
          ReportingEndpoints.validate_config!(123 => "https://example.com")
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "raises an exception when endpoint URL is not a string" do
        expect do
          ReportingEndpoints.validate_config!(default: 123)
        end.to raise_error(ReportingEndpointsConfigError)
      end
    end

    context "with OPT_OUT" do
      it "does not produce a header" do
        expect(ReportingEndpoints.make_header(OPT_OUT)).to be_nil
      end
    end

    context "with nil config" do
      it "does not produce a header" do
        expect(ReportingEndpoints.make_header(nil)).to be_nil
      end
    end
  end
end
