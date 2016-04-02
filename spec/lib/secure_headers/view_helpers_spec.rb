require "spec_helper"
require "erb"

class Message < ERB
  include SecureHeaders::ViewHelpers

  def self.template
<<-TEMPLATE
<% hashed_javascript_tag do %>
  console.log(1)
<% end %>

<% hashed_style_tag do %>
  body {
    background-color: black;
  }
<% end %>

<% nonced_javascript_tag do %>
  body {
    console.log(1)
  }
<% end %>

<% nonced_style_tag do %>
  body {
    background-color: black;
  }
<% end %>
<%= @name %>

TEMPLATE
  end

  def initialize(request, options = {})
    @virtual_path = "/asdfs/index"
    @_request = request
    @template = self.class.template
    super(@template)
  end

  def capture(*args)
    yield(*args)
  end

  def content_tag(type, content = nil, options = nil, &block)
    content = if block_given?
      capture(block)
    end

    if options.is_a?(Hash)
      options = options.map {|k,v| " #{k}=#{v}"}
    end
    "<#{type}#{options}>#{content}</#{type}>"
  end

  def result
    super(binding)
  end

  def request
    @_request
  end
end

module SecureHeaders
  describe ViewHelpers do
    let(:app) { lambda { |env| [200, env, "app"] } }
    let(:middleware) { Middleware.new(app) }

    it "uses view helpers" do
      begin
        allow(SecureRandom).to receive(:base64).and_return("abc123")

        Configuration.default("my_custom_config") do |config|
          config.csp[:script_src] = %w('self')
          config.csp[:style_src] = %w('self')
        end
        request = Rack::Request.new("HTTP_USER_AGENT" => USER_AGENTS[:chrome])
        SecureHeaders.use_secure_headers_override(request, "my_custom_config")

        expected_hash = "sha256-3/URElR9+3lvLIouavYD/vhoICSNKilh15CzI/nKqg8="
        Configuration.instance_variable_set(:@script_hashes, "app/views/asdfs/index.html.erb" => ["'#{expected_hash}'"])
        expected_style_hash = "sha256-7oYK96jHg36D6BM042er4OfBnyUDTG3pH1L8Zso3aGc="
        Configuration.instance_variable_set(:@style_hashes, "app/views/asdfs/index.html.erb" => ["'#{expected_style_hash}'"])

        # render erb that calls out to helpers.
        Message.new(request).result
        _, env = middleware.call request.env

        expect(env[CSP::HEADER_NAME]).to match(/script-src[^;]*'#{Regexp.escape(expected_hash)}'/)
        expect(env[CSP::HEADER_NAME]).to match(/script-src[^;]*'nonce-abc123'/)
        expect(env[CSP::HEADER_NAME]).to match(/style-src[^;]*'nonce-abc123'/)
        expect(env[CSP::HEADER_NAME]).to match(/style-src[^;]*'#{Regexp.escape(expected_style_hash)}'/)
      ensure
        Configuration.instance_variable_set(:@script_hashes, nil)
        Configuration.instance_variable_set(:@style_hashes, nil)
      end
    end
  end
end
