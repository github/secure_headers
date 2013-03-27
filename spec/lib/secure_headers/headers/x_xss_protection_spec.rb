module SecureHeaders
  describe XXssProtection do
    specify { XXssProtection.new.name.should == X_XSS_PROTECTION_HEADER_NAME}
    specify { XXssProtection.new.value.should == "1"}
    specify { XXssProtection.new("0").value.should == "0"}
    specify { XXssProtection.new(:value => 1, :mode => 'block').value.should == '1; mode=block' }

    context "with invalid configuration" do
      it "should raise an error when providing a string that is not valid" do
        lambda {
          XXssProtection.new("asdf")
        }.should raise_error(XXssProtectionBuildError)

        lambda {
          XXssProtection.new("asdf; mode=donkey")
        }.should raise_error(XXssProtectionBuildError)
      end

      context "when using a hash value" do
        it "should allow string values ('1' or '0' are the only valid strings)" do
          lambda {
            XXssProtection.new(:value => '1')
          }.should_not raise_error
        end

        it "should allow integer values (1 or 0 are the only valid integers)" do
          lambda {
            XXssProtection.new(:value => 1)
          }.should_not raise_error
        end

        it "should raise an error if no value key is supplied" do
          lambda {
            XXssProtection.new(:mode => 'block')
          }.should raise_error(XXssProtectionBuildError)
        end

        it "should raise an error if an invalid key is supplied" do
          lambda {
            XXssProtection.new(:value => 123)
          }.should raise_error(XXssProtectionBuildError)
        end

        it "should raise an error if mode != block" do
          lambda {
            XXssProtection.new(:value => 1, :mode => "donkey")
          }.should raise_error(XXssProtectionBuildError)
        end
      end

    end
  end
end