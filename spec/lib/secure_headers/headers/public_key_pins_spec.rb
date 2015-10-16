require 'spec_helper'

module SecureHeaders
  describe PublicKeyPins do
    specify{ expect(PublicKeyPins.new(:max_age => 1234).name).to eq("Public-Key-Pins-Report-Only") }
    specify{ expect(PublicKeyPins.new(:max_age => 1234, :enforce => true).name).to eq("Public-Key-Pins") }

    specify { expect(PublicKeyPins.new({:max_age => 1234}).value).to eq("max-age=1234")}
    specify { expect(PublicKeyPins.new(:max_age => 1234).value).to eq("max-age=1234")}
    specify {
      config = {:max_age => 1234, :pins => [{:sha256 => 'base64encodedpin1'}, {:sha256 => 'base64encodedpin2'}]}
      header_value = "max-age=1234; pin-sha256=\"base64encodedpin1\"; pin-sha256=\"base64encodedpin2\""
      expect(PublicKeyPins.new(config).value).to eq(header_value)
    }

    context "with an invalid configuration" do
      it "raises an exception when max-age is not provided" do
        expect {
          PublicKeyPins.validate_config!(:foo => 'bar')
        }.to raise_error(PublicKeyPinsConfigError)
      end

      it "raises an exception with an invalid max-age" do
        expect {
          PublicKeyPins.validate_config!(:max_age => 'abc123')
        }.to raise_error(PublicKeyPinsConfigError)
      end

      it 'raises an exception with less than 2 pins' do
        expect {
          config = {:max_age => 1234, :pins => [{:sha256 => 'base64encodedpin'}]}
          PublicKeyPins.validate_config!(config)
        }.to raise_error(PublicKeyPinsConfigError)
      end
    end
  end
end
