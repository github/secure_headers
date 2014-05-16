require 'spec_helper'

module SecureHeaders
  describe StrictTransportSecurity do
    specify{ expect(StrictTransportSecurity.new.name).to eq("Strict-Transport-Security") }

    describe "#value" do
      specify { expect(StrictTransportSecurity.new.value).to eq(StrictTransportSecurity::Constants::DEFAULT_VALUE)}
      specify { expect(StrictTransportSecurity.new("max-age=1234").value).to eq("max-age=1234")}
      specify { expect(StrictTransportSecurity.new(:max_age => '1234').value).to eq("max-age=1234")}
      specify { expect(StrictTransportSecurity.new(:max_age => 1234).value).to eq("max-age=1234")}
      specify { expect(StrictTransportSecurity.new(:max_age => HSTS_MAX_AGE, :include_subdomains => true).value).to eq("max-age=#{HSTS_MAX_AGE}; includeSubdomains")}

      context "with an invalid configuration" do
        context "with a hash argument" do
          it "should allow string values for max-age" do
            expect {
              StrictTransportSecurity.new(:max_age => '1234')
            }.not_to raise_error
          end

          it "should allow integer values for max-age" do
            expect {
              StrictTransportSecurity.new(:max_age => 1234)
            }.not_to raise_error
          end

          it "raises an exception with an invalid max-age" do
            expect {
              StrictTransportSecurity.new(:max_age => 'abc123')
            }.to raise_error(STSBuildError)
          end

          it "raises an exception if max-age is not supplied" do
            expect {
              StrictTransportSecurity.new(:includeSubdomains => true)
            }.to raise_error(STSBuildError)
          end
        end

        context "with a string argument" do
          it "raises an exception with an invalid max-age" do
            expect {
              StrictTransportSecurity.new('max-age=abc123')
            }.to raise_error(STSBuildError)
          end

          it "raises an exception if max-age is not supplied" do
            expect {
              StrictTransportSecurity.new('includeSubdomains')
            }.to raise_error(STSBuildError)
          end

          it "raises an exception with an invalid format" do
            expect {
              StrictTransportSecurity.new('max-age=123includeSubdomains')
            }.to raise_error(STSBuildError)
          end
        end
      end
    end
  end
end
