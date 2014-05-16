require 'spec_helper'

module SecureHeaders
  describe XFrameOptions do
    specify{ expect(XFrameOptions.new.name).to eq("X-Frame-Options") }

    describe "#value" do
      specify { expect(XFrameOptions.new.value).to eq(XFrameOptions::Constants::DEFAULT_VALUE)}
      specify { expect(XFrameOptions.new("SAMEORIGIN").value).to eq("SAMEORIGIN")}
      specify { expect(XFrameOptions.new(:value => 'DENY').value).to eq("DENY")}

      context "with invalid configuration" do
        it "allows SAMEORIGIN" do
          expect {
            XFrameOptions.new("SAMEORIGIN").value
          }.not_to raise_error
        end

        it "allows DENY" do
          expect {
            XFrameOptions.new("DENY").value
          }.not_to raise_error        end

        it "allows ALLOW-FROM*" do
          expect {
            XFrameOptions.new("ALLOW-FROM: example.com").value
          }.not_to raise_error
        end
        it "does not allow garbage" do
          expect {
            XFrameOptions.new("I like turtles").value
          }.to raise_error(XFOBuildError)
        end
      end
    end
  end
end
