require 'spec_helper'

module SecureHeaders
  describe StrictTransportSecurity do
    specify{ StrictTransportSecurity.new.name.should == "Strict-Transport-Security" }

    describe "#value" do
      specify { StrictTransportSecurity.new.value.should == StrictTransportSecurity::Constants::DEFAULT_VALUE}
      specify { StrictTransportSecurity.new("max-age=1234").value.should == "max-age=1234"}
      specify { StrictTransportSecurity.new(:max_age => '1234').value.should == "max-age=1234"}
      specify { StrictTransportSecurity.new(:max_age => 1234).value.should == "max-age=1234"}
      specify { StrictTransportSecurity.new(:max_age => HSTS_MAX_AGE, :include_subdomains => true).value.should == "max-age=#{HSTS_MAX_AGE}; includeSubdomains"}

      context "with an invalid configuration" do
        context "with a hash argument" do
          it "should allow string values for max-age" do
            lambda {
              StrictTransportSecurity.new(:max_age => '1234')
            }.should_not raise_error
          end

          it "should allow integer values for max-age" do
            lambda {
              StrictTransportSecurity.new(:max_age => 1234)
            }.should_not raise_error
          end

          it "raises an exception with an invalid max-age" do
            lambda {
              StrictTransportSecurity.new(:max_age => 'abc123')
            }.should raise_error(STSBuildError)
          end

          it "raises an exception if max-age is not supplied" do
            lambda {
              StrictTransportSecurity.new(:includeSubdomains => true)
            }.should raise_error(STSBuildError)
          end
        end

        context "with a string argument" do
          it "raises an exception with an invalid max-age" do
            lambda {
              StrictTransportSecurity.new('max-age=abc123')
            }.should raise_error(STSBuildError)
          end

          it "raises an exception if max-age is not supplied" do
            lambda {
              StrictTransportSecurity.new('includeSubdomains')
            }.should raise_error(STSBuildError)
          end

          it "raises an exception with an invalid format" do
            lambda {
              StrictTransportSecurity.new('max-age=123includeSubdomains')
            }.should raise_error(STSBuildError)
          end
        end
      end
    end
  end
end
