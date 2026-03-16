# frozen_string_literal: true
require "spec_helper"

describe "SecureHeaders::Railtie" do
  # Store initializer blocks so we can execute them in tests
  let(:initializer_blocks) { {} }
  let(:default_headers) { {} }

  before do
    # Clean up any previous Rails/ActiveSupport definitions
    Object.send(:remove_const, :Rails) if defined?(Rails)
    Object.send(:remove_const, :ActiveSupport) if defined?(ActiveSupport)

    # Remove the SecureHeaders::Railtie if it was previously defined
    SecureHeaders.send(:remove_const, :Railtie) if defined?(SecureHeaders::Railtie)

    blocks = initializer_blocks
    headers = default_headers

    # Mock ActiveSupport.on_load to immediately execute the block
    stub_const("ActiveSupport", Module.new do
      define_singleton_method(:on_load) do |name, &block|
        block.call if block
      end
    end)

    # Create mock Rails module with application config
    rails_module = Module.new do
      # Create a mock Railtie base class
      const_set(:Railtie, Class.new do
        define_singleton_method(:isolate_namespace) { |*| }
        define_singleton_method(:initializer) do |name, &block|
          blocks[name] = block
        end
        define_singleton_method(:rake_tasks) { |&block| }
      end)

      # Create mock application with config
      config_action_dispatch = Struct.new(:default_headers).new(headers)
      config_middleware = Object.new.tap do |mw|
        mw.define_singleton_method(:insert_before) { |*| }
      end
      config = Struct.new(:action_dispatch, :middleware).new(config_action_dispatch, config_middleware)
      application = Struct.new(:config).new(config)

      define_singleton_method(:application) { application }
    end

    stub_const("Rails", rails_module)
  end

  def load_railtie
    # Load the railtie file fresh
    load File.expand_path("../../../../lib/secure_headers/railtie.rb", __FILE__)
  end

  def run_action_controller_initializer
    initializer_blocks["secure_headers.action_controller"]&.call
  end

  describe "case-insensitive header removal" do
    context "with Rails default headers (capitalized format like 'X-Frame-Options')" do
      let(:default_headers) do
        {
          "X-Frame-Options" => "SAMEORIGIN",
          "X-XSS-Protection" => "0",
          "X-Content-Type-Options" => "nosniff",
          "X-Permitted-Cross-Domain-Policies" => "none",
          "X-Download-Options" => "noopen",
          "Referrer-Policy" => "strict-origin-when-cross-origin"
        }
      end

      it "removes capitalized conflicting headers from Rails defaults" do
        load_railtie
        run_action_controller_initializer

        expect(default_headers).to be_empty
      end
    end

    context "with lowercase headers (Rack 3+ format)" do
      let(:default_headers) do
        {
          "x-frame-options" => "SAMEORIGIN",
          "x-xss-protection" => "0",
          "x-content-type-options" => "nosniff"
        }
      end

      it "removes lowercase conflicting headers from Rails defaults" do
        load_railtie
        run_action_controller_initializer

        expect(default_headers).to be_empty
      end
    end

    context "with mixed-case headers" do
      let(:default_headers) do
        {
          "X-FRAME-OPTIONS" => "SAMEORIGIN",
          "x-Xss-Protection" => "0",
          "X-Content-Type-OPTIONS" => "nosniff"
        }
      end

      it "removes mixed-case conflicting headers from Rails defaults" do
        load_railtie
        run_action_controller_initializer

        expect(default_headers).to be_empty
      end
    end

    context "preserving non-conflicting headers" do
      let(:default_headers) do
        {
          "X-Frame-Options" => "SAMEORIGIN",
          "X-Custom-Header" => "custom-value",
          "My-Application-Header" => "app-value"
        }
      end

      it "removes only conflicting headers and preserves custom headers" do
        load_railtie
        run_action_controller_initializer

        expect(default_headers).to eq({
          "X-Custom-Header" => "custom-value",
          "My-Application-Header" => "app-value"
        })
      end
    end

    context "with nil default_headers" do
      let(:default_headers) { nil }

      it "handles nil default_headers gracefully" do
        load_railtie

        expect { run_action_controller_initializer }.not_to raise_error
      end
    end

    context "CSP and HSTS headers" do
      let(:default_headers) do
        {
          "Content-Security-Policy" => "default-src 'self'",
          "Content-Security-Policy-Report-Only" => "default-src 'self'",
          "Strict-Transport-Security" => "max-age=31536000"
        }
      end

      it "removes CSP and HSTS headers regardless of case" do
        load_railtie
        run_action_controller_initializer

        expect(default_headers).to be_empty
      end
    end
  end
end
