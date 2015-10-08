require 'spec_helper'

module SecureHeaders
  describe XFrameOptions do
    specify{ expect(XFrameOptions.new.name).to eq("X-Frame-Options") }

    describe "#value" do
      specify { expect(XFrameOptions.new.value).to eq(XFrameOptions::Constants::DEFAULT_VALUE)}
      specify { expect(XFrameOptions.new("SAMEORIGIN").value).to eq("SAMEORIGIN")}
      specify { expect(XFrameOptions.new("DENY").value).to eq("DENY")}

      context "with invalid configuration" do
        it "allows SAMEORIGIN" do
          expect {
            XFrameOptions.validate_config!("SAMEORIGIN")
          }.not_to raise_error
        end

        it "allows DENY" do
          expect {
            XFrameOptions.validate_config!("DENY")
          }.not_to raise_error        end

        it "allows ALLOW-FROM*" do
          expect {
            XFrameOptions.validate_config!("ALLOW-FROM: example.com")
          }.not_to raise_error
        end
        it "does not allow garbage" do
          expect {
            XFrameOptions.validate_config!("I like turtles")
          }.to raise_error(XFOConfigError)
        end
      end
    end
  end
end
