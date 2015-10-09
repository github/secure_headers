require 'spec_helper'

module SecureHeaders
  describe StrictTransportSecurity do
    specify{ expect(StrictTransportSecurity.new.name).to eq("Strict-Transport-Security") }

    describe "#value" do
      specify { expect(StrictTransportSecurity.new.value).to eq(StrictTransportSecurity::DEFAULT_VALUE)}
      specify { expect(StrictTransportSecurity.new("max-age=1234").value).to eq("max-age=1234")}
      specify { expect(StrictTransportSecurity.new("max-age=1234; includeSubdomains").value).to eq("max-age=1234; includeSubdomains")}
      specify { expect(StrictTransportSecurity.new("max-age=1234; includeSubdomains; preload").value).to eq("max-age=1234; includeSubdomains; preload")}

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
