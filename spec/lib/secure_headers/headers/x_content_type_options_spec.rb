module SecureHeaders
  describe XContentTypeOptions do
    specify{ XContentTypeOptions.new.name.should == "X-Content-Type-Options" }

    describe "#value" do
      specify { XContentTypeOptions.new.value.should == XContentTypeOptions::Constants::DEFAULT_VALUE}
      specify { XContentTypeOptions.new("nosniff").value.should == "nosniff"}
      specify { XContentTypeOptions.new(:value => 'nosniff').value.should == "nosniff"}

      context "invalid configuration values" do
        it "accepts nosniff" do
          lambda {
            XContentTypeOptions.new("nosniff")
          }.should_not raise_error

          lambda {
            XContentTypeOptions.new(:value => "nosniff")
          }.should_not raise_error
        end

        it "accepts nil" do
          lambda {
            XContentTypeOptions.new
          }.should_not raise_error
        end

        it "doesn't accept anything besides no-sniff" do
          lambda {
            XContentTypeOptions.new("donkey")
          }.should raise_error
        end
      end
    end
  end
end
