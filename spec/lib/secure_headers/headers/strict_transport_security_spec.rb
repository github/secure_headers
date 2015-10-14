require 'spec_helper'

module SecureHeaders
  describe StrictTransportSecurity do
    describe "#value" do
      specify { expect(StrictTransportSecurity.make_header).to eq([StrictTransportSecurity::HEADER_NAME, StrictTransportSecurity::DEFAULT_VALUE])}
      specify { expect(StrictTransportSecurity.make_header("max-age=1234")).to eq([StrictTransportSecurity::HEADER_NAME, "max-age=1234"])}

      context "with an invalid configuration" do
        context "with a string argument" do
          it "raises an exception with an invalid max-age" do
            expect {
              StrictTransportSecurity.validate_config!('max-age=abc123')
            }.to raise_error(STSConfigError)
          end

          it "raises an exception if max-age is not supplied" do
            expect {
              StrictTransportSecurity.validate_config!('includeSubdomains')
            }.to raise_error(STSConfigError)
          end

          it "raises an exception with an invalid format" do
            expect {
              StrictTransportSecurity.validate_config!('max-age=123includeSubdomains')
            }.to raise_error(STSConfigError)
          end
        end
      end
    end
  end
end
