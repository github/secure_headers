module SecureHeaders
  describe XDownloadOptions do
    specify { expect(XDownloadOptions.make_header).to eq([XDownloadOptions::HEADER_NAME, XDownloadOptions::DEFAULT_VALUE])}
    specify { expect(XDownloadOptions.make_header('noopen')).to eq([XDownloadOptions::HEADER_NAME, 'noopen'])}

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
