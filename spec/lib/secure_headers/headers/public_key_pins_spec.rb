# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe PublicKeyPins do
    specify { expect(PublicKeyPins.new(max_age: 1234, report_only: true).name).to eq("Public-Key-Pins-Report-Only") }
    specify { expect(PublicKeyPins.new(max_age: 1234).name).to eq("Public-Key-Pins") }

    specify { expect(PublicKeyPins.new(max_age: 1234).value).to eq("max-age=1234") }
    specify { expect(PublicKeyPins.new(max_age: 1234).value).to eq("max-age=1234") }
    specify do
      config = { max_age: 1234, pins: [{ sha256: "base64encodedpin1" }, { sha256: "base64encodedpin2" }] }
      header_value = "max-age=1234; pin-sha256=\"base64encodedpin1\"; pin-sha256=\"base64encodedpin2\""
      expect(PublicKeyPins.new(config).value).to eq(header_value)
    end

    context "with an invalid configuration" do
      it "raises an exception when max-age is not provided" do
        expect do
          PublicKeyPins.validate_config!(foo: "bar")
        end.to raise_error(PublicKeyPinsConfigError)
      end

      it "raises an exception with an invalid max-age" do
        expect do
          PublicKeyPins.validate_config!(max_age: "abc123")
        end.to raise_error(PublicKeyPinsConfigError)
      end

      it "raises an exception with less than 2 pins" do
        expect do
          config = { max_age: 1234, pins: [{ sha256: "base64encodedpin" }] }
          PublicKeyPins.validate_config!(config)
        end.to raise_error(PublicKeyPinsConfigError)
      end
    end
  end
end
