require 'spec_helper'

module SecureHeaders
  describe XFrameOptions do
    specify{ XFrameOptions.new.name.should == "X-Frame-Options" }

    describe "#value" do
      specify { XFrameOptions.new.value.should == XFrameOptions::Constants::DEFAULT_VALUE}
      specify { XFrameOptions.new("SAMEORIGIN").value.should == "SAMEORIGIN"}
      specify { XFrameOptions.new(:value => 'DENY').value.should == "DENY"}

      context "with invalid configuration" do
        it "allows SAMEORIGIN" do
          lambda {
            XFrameOptions.new("SAMEORIGIN").value
          }.should_not raise_error(XFOBuildError)
        end

        it "allows DENY" do
          lambda {
            XFrameOptions.new("DENY").value
          }.should_not raise_error(XFOBuildError)
        end

        it "allows ALLOW-FROM*" do
          lambda {
            XFrameOptions.new("ALLOW-FROM: example.com").value
          }.should_not raise_error(XFOBuildError)
        end
        it "does not allow garbage" do
          lambda {
            XFrameOptions.new("I like turtles").value
          }.should raise_error(XFOBuildError)
        end
      end
    end
  end
end
