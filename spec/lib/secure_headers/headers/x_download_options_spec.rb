module SecureHeaders
  describe XDownloadOptions do
    specify { expect(XDownloadOptions.new.name).to eq(XDO_HEADER_NAME)}
    specify { expect(XDownloadOptions.new.value).to eq("noopen")}
    specify { expect(XDownloadOptions.new('noopen').value).to eq('noopen')}
    specify { expect(XDownloadOptions.new(:value => 'noopen').value).to eq('noopen') }

    context "invalid configuration values" do
      it "accepts noopen" do
        expect {
          XDownloadOptions.new("noopen")
        }.not_to raise_error

        expect {
          XDownloadOptions.new(:value => "noopen")
        }.not_to raise_error
      end

      it "accepts nil" do
        expect {
          XDownloadOptions.new
        }.not_to raise_error
      end

      it "doesn't accept anything besides noopen" do
        expect {
          XDownloadOptions.new("open")
        }.to raise_error(XDOBuildError)
      end
    end
  end
end
