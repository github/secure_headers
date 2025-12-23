# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Configuration do
    before(:each) do
      reset_config
    end

    it "has a default config" do
      expect(Configuration.default).to_not be_nil
    end

    it "has an 'noop' override" do
      Configuration.default
      expect(Configuration.overrides(Configuration::NOOP_OVERRIDE)).to_not be_nil
    end

    it "dup results in a copy of the default config" do
      Configuration.default
      original_configuration = Configuration.send(:default_config)
      configuration = Configuration.dup
      expect(original_configuration).not_to be(configuration)
      Configuration::CONFIG_ATTRIBUTES.each do |attr|
        # rubocop:disable GitHub/AvoidObjectSendWithDynamicMethod
        expect(original_configuration.public_send(attr)).to eq(configuration.public_send(attr))
        # rubocop:enable GitHub/AvoidObjectSendWithDynamicMethod
      end
    end

    it "stores an override" do
      Configuration.override(:test_override) do |config|
        config.x_frame_options = "DENY"
      end

      expect(Configuration.overrides(:test_override)).to_not be_nil
    end

    describe "#override" do
      it "raises on configuring an existing override" do
        set_override = Proc.new {
          Configuration.override(:test_override) do |config|
            config.x_frame_options = "DENY"
          end
        }

        set_override.call

        expect { set_override.call }
          .to raise_error(Configuration::AlreadyConfiguredError, "Configuration already exists")
      end

      it "raises when a named append with the given name exists" do
        Configuration.named_append(:test_override) do |config|
          config.x_frame_options = "DENY"
        end

        expect do
          Configuration.override(:test_override) do |config|
            config.x_frame_options = "SAMEORIGIN"
          end
        end.to raise_error(Configuration::AlreadyConfiguredError, "Configuration already exists")
      end
    end

    describe "#named_append" do
      it "raises on configuring an existing append" do
        set_override = Proc.new {
          Configuration.named_append(:test_override) do |config|
            config.x_frame_options = "DENY"
          end
        }

        set_override.call

        expect { set_override.call }
          .to raise_error(Configuration::AlreadyConfiguredError, "Configuration already exists")
      end

      it "raises when an override with the given name exists" do
        Configuration.override(:test_override) do |config|
          config.x_frame_options = "DENY"
        end

        expect do
          Configuration.named_append(:test_override) do |config|
            config.x_frame_options = "SAMEORIGIN"
          end
        end.to raise_error(Configuration::AlreadyConfiguredError, "Configuration already exists")
      end
    end

    it "deprecates the secure_cookies configuration" do
      expect {
        Configuration.default do |config|
          config.secure_cookies = true
        end
      }.to raise_error(ArgumentError)
    end

    it "gives cookies a default config" do
      expect(Configuration.default.cookies).to eq({ httponly: true, secure: true, samesite: { lax: true } })
    end

    it "allows OPT_OUT" do
      Configuration.default do |config|
        config.cookies = OPT_OUT
      end

      config = Configuration.dup
      expect(config.cookies).to eq(OPT_OUT)
    end

    it "allows me to be explicit too" do
      Configuration.default do |config|
        config.cookies = { httponly: true, secure: true, samesite: { lax: false } }
      end

      config = Configuration.dup
      expect(config.cookies).to eq({ httponly: true, secure: true, samesite: { lax: false } })
    end

    describe ".disable!" do
      it "disables secure_headers completely" do
        Configuration.disable!
        expect(Configuration.disabled?).to be true
      end

      it "returns a noop config when disabled" do
        Configuration.disable!
        config = Configuration.send(:default_config)
        Configuration::CONFIG_ATTRIBUTES.each do |attr|
          expect(config.instance_variable_get("@#{attr}")).to eq(OPT_OUT)
        end
      end

      it "does not raise NotYetConfiguredError when disabled without default config" do
        Configuration.disable!
        expect { Configuration.send(:default_config) }.not_to raise_error
      end

      it "registers the NOOP_OVERRIDE when disabled without calling default" do
        Configuration.disable!
        expect(Configuration.overrides(Configuration::NOOP_OVERRIDE)).to_not be_nil
      end

      it "raises AlreadyConfiguredError when called after default" do
        Configuration.default do |config|
          config.csp = { default_src: %w('self'), script_src: %w('self') }
        end

        expect {
          Configuration.disable!
        }.to raise_error(Configuration::AlreadyConfiguredError, "Configuration already set, cannot disable")
      end

      it "raises AlreadyConfiguredError when default is called after disable!" do
        Configuration.disable!

        expect {
          Configuration.default do |config|
            config.csp = { default_src: %w('self'), script_src: %w('self') }
          end
        }.to raise_error(Configuration::AlreadyConfiguredError, "Configuration has been disabled, cannot set default")
      end

      it "allows default to be called after disable! and reset_config" do
        Configuration.disable!
        reset_config

        expect {
          Configuration.default do |config|
            config.csp = { default_src: %w('self'), script_src: %w('self') }
          end
        }.not_to raise_error

        # After reset_config, disabled? returns nil (not false) because @disabled is removed
        expect(Configuration.disabled?).to be_falsy
        expect(Configuration.instance_variable_defined?(:@default_config)).to be true
      end

      it "works correctly with dup when library is disabled" do
        Configuration.disable!
        config = Configuration.dup

        Configuration::CONFIG_ATTRIBUTES.each do |attr|
          expect(config.instance_variable_get("@#{attr}")).to eq(OPT_OUT)
        end
      end

      it "does not interfere with override mechanism" do
        Configuration.disable!

        # Should be able to use opt_out_of_all_protection without error
        request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
        expect {
          SecureHeaders.opt_out_of_all_protection(request)
        }.not_to raise_error
      end

      it "interacts correctly with named overrides when disabled" do
        Configuration.disable!

        Configuration.override(:test_override) do |config|
          config.x_frame_options = "DENY"
        end

        expect(Configuration.overrides(:test_override)).to_not be_nil
      end
    end
  end
end
