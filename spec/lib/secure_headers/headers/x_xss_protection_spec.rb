module SecureHeaders
  describe XXssProtection do
    specify { expect(XXssProtection.new.name).to eq(X_XSS_PROTECTION_HEADER_NAME)}
    specify { expect(XXssProtection.new.value).to eq("1")}
    specify { expect(XXssProtection.new("0").value).to eq("0")}
    specify { expect(XXssProtection.new("1; mode=block").value).to eq('1; mode=block') }
    specify { expect(XXssProtection.new("1; mode=block; report=https://www.secure.com/reports").value).to eq('1; mode=block; report=https://www.secure.com/reports') }

    context "with invalid configuration" do
      it "should raise an error when providing a string that is not valid" do
        expect {
          XXssProtection.validate_config!("asdf")
        }.to raise_error(XXssProtectionConfigError)

        expect {
          XXssProtection.validate_config!("asdf; mode=donkey")
        }.to raise_error(XXssProtectionConfigError)
      end

      context "when using a hash value" do
        it "should allow string values ('1' or '0' are the only valid strings)" do
          expect {
            XXssProtection.validate_config!('1')
          }.not_to raise_error
        end

        it "should raise an error if no value key is supplied" do
          expect {
            XXssProtection.validate_config!("mode=block")
          }.to raise_error(XXssProtectionConfigError)
        end

        it "should raise an error if an invalid key is supplied" do
          expect {
            XXssProtection.validate_config!("123")
          }.to raise_error(XXssProtectionConfigError)
        end

        it "should raise an error if mode != block" do
          expect {
            XXssProtection.validate_config!("1; mode=donkey")
          }.to raise_error(XXssProtectionConfigError)
        end
      end

    end
  end
end
