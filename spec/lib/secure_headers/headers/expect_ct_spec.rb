require 'spec_helper'

module SecureHeaders
  describe ExpectCt do
    specify { expect(ExpectCt.new(max_age: 1234, enforce: true).value).to eq("enforce; max-age=1234") }
    specify { expect(ExpectCt.new(max_age: 1234, enforce: false).value).to eq("max-age=1234") }
    specify { expect(ExpectCt.new(max_age: 1234, enforce: 'yolocopter').value).to eq("max-age=1234") }
    specify { expect(ExpectCt.new(max_age: 1234, report_uri: 'https://report-uri.io/expect-ct').value).to eq("max-age=1234; report-uri=\"https://report-uri.io/expect-ct\"") }
    specify do
      config = { enforce: true, max_age: 1234, report_uri: 'https://report-uri.io/expect-ct' }
      header_value = "enforce; max-age=1234; report-uri=\"https://report-uri.io/expect-ct\""
      expect(ExpectCt.new(config).value).to eq(header_value)
    end

    context "with an invalid configuration" do
      it "raises an exception when configuration isn't a hash" do
        expect do
          ExpectCt.validate_config!(%w(a))
        end.to raise_error(ExpectCtConfigError)
      end

      it "raises an exception when max-age is not provided" do
        expect do
          ExpectCt.validate_config!(foo: 'bar')
        end.to raise_error(ExpectCtConfigError)
      end

      it "raises an exception with an invalid max-age" do
        expect do
          ExpectCt.validate_config!(max_age: 'abc123')
        end.to raise_error(ExpectCtConfigError)
      end

      it "raises an exception with an invalid enforce value" do
        expect do
          ExpectCt.validate_config!(enforce: 'brokenstring')
        end.to raise_error(ExpectCtConfigError)
      end
    end
  end
end
