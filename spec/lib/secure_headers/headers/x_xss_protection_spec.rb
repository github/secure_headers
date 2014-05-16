module SecureHeaders
  describe XXssProtection do
    specify { expect(XXssProtection.new.name).to eq(X_XSS_PROTECTION_HEADER_NAME)}
    specify { expect(XXssProtection.new.value).to eq("1")}
    specify { expect(XXssProtection.new("0").value).to eq("0")}
    specify { expect(XXssProtection.new(:value => 1, :mode => 'block').value).to eq('1; mode=block') }

    context "with invalid configuration" do
      it "should raise an error when providing a string that is not valid" do
        expect {
          XXssProtection.new("asdf")
        }.to raise_error(XXssProtectionBuildError)

        expect {
          XXssProtection.new("asdf; mode=donkey")
        }.to raise_error(XXssProtectionBuildError)
      end

      context "when using a hash value" do
        it "should allow string values ('1' or '0' are the only valid strings)" do
          expect {
            XXssProtection.new(:value => '1')
          }.not_to raise_error
        end

        it "should allow integer values (1 or 0 are the only valid integers)" do
          expect {
            XXssProtection.new(:value => 1)
          }.not_to raise_error
        end

        it "should raise an error if no value key is supplied" do
          expect {
            XXssProtection.new(:mode => 'block')
          }.to raise_error(XXssProtectionBuildError)
        end

        it "should raise an error if an invalid key is supplied" do
          expect {
            XXssProtection.new(:value => 123)
          }.to raise_error(XXssProtectionBuildError)
        end

        it "should raise an error if mode != block" do
          expect {
            XXssProtection.new(:value => 1, :mode => "donkey")
          }.to raise_error(XXssProtectionBuildError)
        end
      end

    end
  end
end