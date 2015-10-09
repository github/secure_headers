module SecureHeaders
  describe XContentTypeOptions do
    specify{ expect(XContentTypeOptions.new.name).to eq("X-Content-Type-Options") }

    describe "#value" do
      specify { expect(XContentTypeOptions.new.value).to eq(XContentTypeOptions::DEFAULT_VALUE)}
      specify { expect(XContentTypeOptions.new("nosniff").value).to eq("nosniff")}

      context "invalid configuration values" do
        it "accepts nosniff" do
          expect {
            XContentTypeOptions.validate_config!("nosniff")
          }.not_to raise_error
        end

        it "accepts nil" do
          expect {
            XContentTypeOptions.validate_config!(nil)
          }.not_to raise_error
        end

        it "doesn't accept anything besides no-sniff" do
          expect {
            XContentTypeOptions.validate_config!("donkey")
          }.to raise_error(XContentTypeOptionsConfigError)
        end
      end
    end
  end
end
