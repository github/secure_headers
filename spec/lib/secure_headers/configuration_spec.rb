# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Configuration do
    before(:each) do
      reset_config
      Configuration.default
    end

    it "has a default config" do
      expect(Configuration.default).to_not be_nil
    end

    it "has an 'noop' override" do
      expect(Configuration.overrides(Configuration::NOOP_OVERRIDE)).to_not be_nil
    end

    it "stores an override" do
      Configuration.override(:test_override) do |config|
        config.x_frame_options = "DENY"
      end

      expect(Configuration.overrides(:test_override)).to_not be_nil
    end

    it "deprecates the secure_cookies configuration" do
      expect {
        Configuration.default do |config|
          config.secure_cookies = true
        end
      }.to raise_error(ArgumentError)
    end

    it "gives cookies a default config" do
      expect(Configuration.default.cookies).to eq({httponly: true, secure: true, samesite: {lax: true}})
    end

    it "allows OPT_OUT" do
      Configuration.default do |config|
        config.cookies = OPT_OUT
      end

      config = Configuration.get
      expect(config.cookies).to eq(OPT_OUT)
    end

    it "allows me to be explicit too" do
      Configuration.default do |config|
        config.cookies = {httponly: true, secure: true, samesite: {lax: false}}
      end

      config = Configuration.get
      expect(config.cookies).to eq({httponly: true, secure: true, samesite: {lax: false}})
    end
  end
end
