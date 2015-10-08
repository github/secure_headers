module SecureHeaders
  describe XDownloadOptions do
    specify { expect(XDownloadOptions.new.name).to eq(XDO_HEADER_NAME)}
    specify { expect(XDownloadOptions.new.value).to eq("noopen")}
    specify { expect(XDownloadOptions.new('noopen').value).to eq('noopen')}

    context "invalid configuration values" do
      it "accepts noopen" do
        expect {
          XDownloadOptions.validate_config!("noopen")
        }.not_to raise_error
      end

      it "accepts nil" do
        expect {
          XDownloadOptions.validate_config!(nil)
        }.not_to raise_error
      end

      it "doesn't accept anything besides noopen" do
        expect {
          XDownloadOptions.validate_config!("open")
        }.to raise_error(XDOConfigError)
      end
    end
  end
end
