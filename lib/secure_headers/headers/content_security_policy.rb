require 'uri'
require 'brwsr'

module SecureHeaders
  class ContentSecurityPolicyBuildError < StandardError; end

  class ContentSecurityPolicy
    module Constants
      STANDARD_CSP_HEADER = "default-src https: data: 'unsafe-inline' 'unsafe-eval'; frame-src https://* about: javascript:; img-src chrome-extension:"
      STANDARD_HEADER_NAME = "Content-Security-Policy"
      DIRECTIVES = [:default_src, :script_src, :frame_src, :style_src, :img_src, :media_src, :font_src, :object_src, :connect_src]
      META = [:enforce, :http_additions, :disable_chrome_extension, :disable_fill_missing, :forward_endpoint]
    end
    include Constants

    attr_accessor *META
    attr_reader :browser, :ssl_request, :report_uri, :request_uri

    alias :enforce? :enforce
    alias :disable_chrome_extension? :disable_chrome_extension
    alias :disable_fill_missing? :disable_fill_missing
    alias :ssl_request? :ssl_request

    def self.build(request, config)
      browser = Brwsr::Browser.new(:ua => request.env['HTTP_USER_AGENT'])

      klass = case
      when browser.ie?
        self
      when browser.firefox?
        FirefoxContentSecurityPolicy
      else
        WebkitContentSecurityPolicy
      end

      klass.new(request, config)
    end

    def initialize request = nil, config = nil
      if config
        configure request, config
      elsif request
        parse_request request
      end
    end

    def configure request, opts
      @config = opts.dup

      parse_request request
      META.each do |meta|
        self.send("#{meta}=", @config.delete(meta))
      end

      @report_uri = @config.delete(:report_uri)

      after_configure
    end

    def after_configure
      normalize_csp_options
    end

    def base_name
      STANDARD_HEADER_NAME
    end

    def name
      base = base_name
      base += "-Report-Only" unless enforce
      base
    end

    def directives
      DIRECTIVES
    end

    def value
      return @config if @config.is_a?(String)

      if @config.nil?
        csp_header
      else
        build_value
      end
    end

    def csp_header
      STANDARD_CSP_HEADER
    end

    private

    def build_value
      fill_directives unless disable_fill_missing?
      add_missing_chrome_extension_values unless disable_chrome_extension?
      append_http_additions unless ssl_request?

      header_value = build_impl_specific_directives
      header_value += generic_directives(@config)
      header_value += report_uri_directive(@report_uri)

      #store the value for next time
      @config = header_value
      header_value.strip
    rescue StandardError => e
      raise ContentSecurityPolicyBuildError.new("Couldn't build CSP header :( #{e}")
    end

    def fill_directives
      return unless @config[:default_src]

      default = @config[:default_src]
      directives.each do |directive|
        unless @config[directive]
          @config[directive] = default
        end
      end
      @config
    end

    def add_missing_chrome_extension_values
      directives.each do |directive|
        next unless @config[directive]
        if !@config[directive].include?('chrome-extension:')
          @config[directive] << 'chrome-extension:'
        end
      end
    end

    def append_http_additions
      return unless http_additions

      http_additions.each do |k, v|
        @config[k] ||= []
        @config[k] << v
      end
    end

    def normalize_csp_options
      @config.each do |k,v|
        @config[k] = v.split if v.is_a? String
        @config[k] = @config[k].map do |val|
          translate_dir_value(val)
        end
      end
    end

    # translates 'inline','self', 'none' and 'eval' to their respective impl-specific values.
    def translate_dir_value val
      if %w{inline eval}.include?(val)
        translate_inline_or_eval(val)
        # self/none are special sources/src-dir-values and need to be quoted in chrome
      elsif %{self none}.include?(val)
        "'#{val}'"
      else
        val
      end
    end

    # inline/eval => impl-specific values
    def translate_inline_or_eval val
      val == 'inline' ? "'unsafe-inline'" : "'unsafe-eval'"
    end

    def build_impl_specific_directives
      header_value = ""
      default = expect_directive_value(:default_src)
      header_value += "default-src #{default.join(" ")}; " if default.any?
      header_value
    end

    def expect_directive_value key
      @config.delete(key) {|k| raise ContentSecurityPolicyBuildError.new("Expected to find #{k} directive value")}
    end

    # moves inline/eval values from script-src to options
    # discards those values in the style-src directive
    def build_options_directive
      options_directive = []
      @config.each do |directive, val|
        next if val.is_a?(String)
        new_val = []
        val.each do |token|
          if ['inline-script', 'eval-script'].include?(token)
            # Firefox does not support blocking inline styles ATM
            # https://bugzilla.mozilla.org/show_bug.cgi?id=763879
            unless directive?(directive, "style_src") || options_directive.include?(token)
              options_directive << token
            end
          else
            new_val << token
          end
        end
        @config[directive] = new_val
      end

      options_directive
    end

    def same_origin?
      origin = URI.parse(request_uri)
      uri = URI.parse(report_uri)
      uri.host == origin.host && origin.port == uri.port && origin.scheme == uri.scheme
    end

    def directive? val, name
      val.to_s.casecmp(name) == 0
    end

    def report_uri_directive(report_uri)
      report_uri.nil? ? '' : "report-uri #{report_uri};"
    end

    def generic_directives(config)
      header_value = ''
      config.keys.sort_by{|k| k.to_s}.each do |k| # ensure consistent ordering
        header_value += "#{symbol_to_hyphen_case(k)} #{config[k].join(" ")}; "
      end

      header_value
    end

    def symbol_to_hyphen_case sym
      sym.to_s.gsub('_', '-')
    end

    def parse_request request
      @browser = Brwsr::Browser.new(:ua => request.env['HTTP_USER_AGENT'])
      @ssl_request = request.ssl?
      @request_uri = if defined? ActionDispatch::Request
        # rails 3
        request.original_url
      else
        # rails 2
        request.url
      end
    end
  end
end
