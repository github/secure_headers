require 'spec_helper'

module SecureHeaders
  describe XFrameOptions do
    describe "#value" do
      specify { expect(XFrameOptions.make_header).to eq([XFrameOptions::HEADER_NAME, XFrameOptions::DEFAULT_VALUE])}
      specify { expect(XFrameOptions.make_header("DENY")).to eq([XFrameOptions::HEADER_NAME, "DENY"])}

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
