# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe ReportingEndpoints do
    describe "make_header" do
      it "returns nil with nil config" do
        expect(described_class.make_header).to be_nil
      end

      it "returns nil with opt-out config" do
        expect(described_class.make_header(OPT_OUT)).to be_nil
      end

      it "returns an empty string with empty config" do
        name, value = described_class.make_header({})
        expect(name).to eq(ReportingEndpoints::HEADER_NAME)
        expect(value).to eq("")
      end

      it "builds a valid header with correct configuration" do
        name, value = described_class.make_header({endpoint: "https://report-endpoint-example.io/"})
        expect(name).to eq(ReportingEndpoints::HEADER_NAME)
        expect(value).to eq("endpoint=\"https://report-endpoint-example.io/\"")
      end

      it "supports multiple endpoints" do
        name, value = described_class.make_header({
          endpoint: "https://report-endpoint-example.io/",
          'csp-endpoint': "https://csp-report-endpoint-example.io/"
          })
        expect(name).to eq(ReportingEndpoints::HEADER_NAME)
        expect(value).to eq("endpoint=\"https://report-endpoint-example.io/\",csp-endpoint=\"https://csp-report-endpoint-example.io/\"")
      end
    end

    describe "validate_config!" do
      it "raises an exception when configuration is not a hash" do
        expect do
          described_class.validate_config!(["invalid-configuration"])
        end.to raise_error(ReportingEndpointsConfigError)
      end

      it "raises an exception when all hash elements are not a string" do
        expect do
          described_class.validate_config!({endpoint: 1234})
        end.to raise_error(ReportingEndpointsConfigError)
      end
    end
  end
end
