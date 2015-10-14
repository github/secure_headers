require 'spec_helper'

module SecureHeaders
  describe XContentTypeOptions do
    describe "#value" do
      specify { expect(XContentTypeOptions.make_header).to eq([XContentTypeOptions::HEADER_NAME, XContentTypeOptions::DEFAULT_VALUE])}
      specify { expect(XContentTypeOptions.make_header("nosniff")).to eq([XContentTypeOptions::HEADER_NAME, "nosniff"])}

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
