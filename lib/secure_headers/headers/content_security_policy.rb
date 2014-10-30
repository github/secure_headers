require 'uri'
require 'base64'
require 'securerandom'

module SecureHeaders
  class ContentSecurityPolicyBuildError < StandardError; end
  class ContentSecurityPolicy < Header
    module Constants
      DEFAULT_CSP_HEADER = "default-src https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https: about: javascript:; img-src data:"
      HEADER_NAME = "Content-Security-Policy"
      DIRECTIVES = [
        # :base_uri, disabled because this doesn't use the default-src value if empty
        # :child_src, disabled because this doesn't use the default-src value if empty
        :connect_src,
        :default_src,
        :font_src,
        # :form_action, disabled because this doesn't use the default-src value if empty
        :frame_src,
        # :frame_ancestors, disabled because this doesn't use the default-src value if empty
        :img_src,
        :media_src,
        :object_src,
        # :plugin_types, disabled because this doesn't use the default-src value if empty
        # :referrer, disabled because this doesn't use the default-src value if empty
        # :reflected_xss, disabled because this doesn't use the default-src value if empty
        :script_src,
        :style_src
      ]
    end
    include Constants

    attr_reader :disable_fill_missing, :ssl_request
    alias :disable_fill_missing? :disable_fill_missing
    alias :ssl_request? :ssl_request

    # +options+ param contains
    # :ssl_request used to determine if http_additions should be used
    # :ua the user agent (or just use Firefox/Chrome/MSIE/etc)
    #
    # :report used to determine what :ssl_request, :ua, and :request_uri are set to
    def initialize(config=nil, options={})
      @controller = options[:controller]

      if options[:request]
        parse_request(options[:request])
      else
        @ua = options[:ua]
        # fails open, assumes http. Bad idea? Will always include http additions.
        # could also fail if not supplied.
        @ssl_request = !!options[:ssl]
        # a nil value here means we always assume we are not on the same host,
        # which causes all FF csp reports to go through the forwarder
        @request_uri = options[:request_uri]
      end

      configure(config) if config
    end

    def nonce
      @nonce ||= SecureRandom.base64(32).chomp
    end

    def configure(config)
      @config = config.dup
      # these values don't support lambdas because this needs to be rewritten
      @http_additions = @config.delete(:http_additions)
      @app_name = @config.delete(:app_name)

      normalize_csp_config

      @disable_fill_missing = @config.delete(:disable_fill_missing)
      @enforce = !!@config.delete(:enforce)
      @tag_report_uri = @config.delete(:tag_report_uri)

      fill_directives unless disable_fill_missing?
    end

    def name
      base = HEADER_NAME
      if !@enforce
        base += "-Report-Only"
      end
      base
    end

    def value
      return @config if @config.is_a?(String)
      if @config
        build_value
      else
        DEFAULT_CSP_HEADER
      end
    end

    private

    def build_value
      raise "Expected to find default_src directive value" unless @config[:default_src]
      append_http_additions unless ssl_request?
      header_value = [
        generic_directives(@config),
        report_uri_directive
      ].join.strip
    end

    def fill_directives
      return unless @config[:default_src]
      default = @config[:default_src]
      DIRECTIVES.each do |directive|
        unless @config[directive]
          @config[directive] = default
        end
      end
      @config
    end

    def append_http_additions
      return unless @http_additions
      @http_additions.each do |k, v|
        @config[k] ||= []
        @config[k] << v
      end
    end

    def normalize_csp_config
      @config = @config.inject({}) do |hash, (key, value)|
        # lambdas
        config_val = value.respond_to?(:call) ? value.call : value
        # space-delimeted strings
        config_val = config_val.split if config_val.is_a? String
        # array of strings
        if config_val.respond_to?(:map) #skip booleans
          config_val = config_val.map do |val|
            translate_dir_value(val)
          end.flatten.uniq
        end

        hash[key] = config_val
        hash
      end

      @report_uri = @config.delete(:report_uri).join(" ") if @config[:report_uri]
    end

    # translates 'inline','self', 'none' and 'eval' to their respective impl-specific values.
    def translate_dir_value val
      if %w{inline eval}.include?(val)
        val == 'inline' ? "'unsafe-inline'" : "'unsafe-eval'"
        # self/none are special sources/src-dir-values and need to be quoted in chrome
      elsif %{self none}.include?(val)
        "'#{val}'"
      elsif val == 'nonce'
        @controller.instance_variable_set(:@content_security_policy_nonce, nonce)
        ["'nonce-#{nonce}'", "'unsafe-inline'"]
      else
        val
      end
    end

    def report_uri_directive
      return '' if @report_uri.nil?

      if @report_uri.start_with?('//')
        @report_uri = if @ssl_request
                        "https:" + @report_uri
                      else
                        "http:" + @report_uri
                      end
      end

      if @tag_report_uri
        @report_uri = "#{@report_uri}?enforce=#{@enforce}"
        @report_uri += "&app_name=#{@app_name}" if @app_name
      end

      "report-uri #{@report_uri};"
    end

    def generic_directives(config)
      header_value = ''
      if config[:img_src]
        config[:img_src] = config[:img_src] + ['data:'] unless config[:img_src].include?('data:')
      else
        config[:img_src] = config[:default_src] + ['data:']
      end

      header_value = build_directive(:default_src)
      config.keys.sort_by{|k| k.to_s}.each do |k| # ensure consistent ordering
        header_value += build_directive(k)
      end

      header_value
    end

    # build and deletes the directive
    def build_directive(key)
      "#{symbol_to_hyphen_case(key)} #{@config.delete(key).join(" ")}; "
    end

    def symbol_to_hyphen_case sym
      sym.to_s.gsub('_', '-')
    end

    def parse_request request
      @ssl_request = request.ssl?
      @ua = request.env['HTTP_USER_AGENT']
      @request_uri = if request.respond_to?(:original_url)
        # rails 3.1+
        request.original_url
      else
        # rails 2/3.0
        request.url
      end
    end
  end
end
