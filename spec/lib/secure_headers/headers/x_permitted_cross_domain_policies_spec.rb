module SecureHeaders
  describe XPermittedCrossDomainPolicies do
    specify { expect(XPermittedCrossDomainPolicies.new.name).to eq(XPermittedCrossDomainPolicies::Constants::XPCDP_HEADER_NAME)}
    specify { expect(XPermittedCrossDomainPolicies.new.value).to eq("none")}
    specify { expect(XPermittedCrossDomainPolicies.new('master-only').value).to eq('master-only')}
    specify { expect(XPermittedCrossDomainPolicies.new(:value => 'master-only').value).to eq('master-only') }

    context "valid configuration values" do
      it "accepts 'all'" do
        expect {
          XPermittedCrossDomainPolicies.new("all")
        }.not_to raise_error

        expect {
          XPermittedCrossDomainPolicies.new(:value => "all")
        }.not_to raise_error
      end

      it "accepts 'by-ftp-filename'" do
        expect {
          XPermittedCrossDomainPolicies.new("by-ftp-filename")
        }.not_to raise_error

        expect {
          XPermittedCrossDomainPolicies.new(:value => "by-ftp-filename")
        }.not_to raise_error
      end

      it "accepts 'by-content-type'" do
        expect {
          XPermittedCrossDomainPolicies.new("by-content-type")
        }.not_to raise_error

        expect {
          XPermittedCrossDomainPolicies.new(:value => "by-content-type")
        }.not_to raise_error
      end
      it "accepts 'master-only'" do
        expect {
          XPermittedCrossDomainPolicies.new("master-only")
        }.not_to raise_error

        expect {
          XPermittedCrossDomainPolicies.new(:value => "master-only")
        }.not_to raise_error
      end

      it "accepts nil" do
        expect {
          XPermittedCrossDomainPolicies.new
        }.not_to raise_error
      end
    end

    context 'invlaid configuration values' do

      it "doesn't accept invalid values" do
        expect {
          XPermittedCrossDomainPolicies.new("open")
        }.to raise_error(XPCDPBuildError)
      end
    end
  end
end
