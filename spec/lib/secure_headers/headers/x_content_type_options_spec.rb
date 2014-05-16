module SecureHeaders
  describe XContentTypeOptions do
    specify{ expect(XContentTypeOptions.new.name).to eq("X-Content-Type-Options") }

    describe "#value" do
      specify { expect(XContentTypeOptions.new.value).to eq(XContentTypeOptions::Constants::DEFAULT_VALUE)}
      specify { expect(XContentTypeOptions.new("nosniff").value).to eq("nosniff")}
      specify { expect(XContentTypeOptions.new(:value => 'nosniff').value).to eq("nosniff")}

      context "invalid configuration values" do
        it "accepts nosniff" do
          expect {
            XContentTypeOptions.new("nosniff")
          }.not_to raise_error

          expect {
            XContentTypeOptions.new(:value => "nosniff")
          }.not_to raise_error
        end

        it "accepts nil" do
          expect {
            XContentTypeOptions.new
          }.not_to raise_error
        end

        it "doesn't accept anything besides no-sniff" do
          expect {
            XContentTypeOptions.new("donkey")
          }.to raise_error
        end
      end
    end
  end
end
