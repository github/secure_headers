require 'spec_helper'
require 'secure_headers/headers/content_security_policy/script_hash_middleware'

module SecureHeaders
  describe ContentSecurityPolicy::ScriptHashMiddleware do

    let(:app) { double(:call => [200, headers, '']) }
    let(:env) { double }
    let(:headers) { double }

    let(:default_config) do
      {
        :disable_fill_missing => true,
        :default_src => 'https://*',
        :report_uri => '/csp_report',
        :script_src => 'inline eval https://* data:',
        :style_src => "inline https://* about:"
      }
    end

    def should_assign_header name, value
      expect(headers).to receive(:[]=).with(name, value)
    end

    def call_middleware(hashes = [])
      options = {
        :ua => USER_AGENTS[:chrome]
      }
      expect(env).to receive(:[]).with(HASHES_ENV_KEY).and_return(hashes)
      expect(env).to receive(:[]).with(ENV_KEY).and_return(
        :config => default_config,
        :options => options
      )
      ContentSecurityPolicy::ScriptHashMiddleware.new(app).call(env)
    end

    it "adds hashes stored in env to the header" do
      should_assign_header(HEADER_NAME + "-Report-Only", /script-src[^;]*'sha256-/)
      call_middleware(['sha256-abc123'])
    end

    it "leaves things alone when no hashes are saved to env" do
      should_assign_header(HEADER_NAME + "-Report-Only", /script-src[^;]*(?!'sha256-)/)
      call_middleware()
    end
  end
end
