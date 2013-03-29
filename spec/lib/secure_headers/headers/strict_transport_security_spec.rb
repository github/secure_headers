require 'spec_helper'

module SecureHeaders
  describe StrictTransportSecurity do
    specify{ StrictTransportSecurity.new.name.should == "Strict-Transport-Security" }

    describe "#value" do
      it "sets Strict Transport Security headers" do
        s = StrictTransportSecurity.new
        s.value.should == StrictTransportSecurity::Constants::DEFAULT_VALUE
      end

      it "allows you to specify includeSubdomains" do
        s = StrictTransportSecurity.new(:max_age => HSTS_MAX_AGE, :include_subdomains => true)
        s.value.should == "max-age=#{HSTS_MAX_AGE}; includeSubdomains"
      end

      it "accepts a string value and returns verbatim" do
        s = StrictTransportSecurity.new('max-age=1234')
        s.value.should == "max-age=1234"
      end

      it "allows you to specify max-age" do
        age = '8675309'
        s = StrictTransportSecurity.new(:max_age => age)
        s.value.should == "max-age=#{age}"
      end

      it "allows integer values for max-age" do
        age = 99
        s = StrictTransportSecurity.new(:max_age => age)
        s.value.should == "max-age=#{age}"
      end

      context "with an invalid configuration" do
        context "with a hash argument" do
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
