# frozen_string_literal: true
module SecureHeaders
  class PublicKeyPinsConfigError < StandardError; end
  class PublicKeyPins
    HEADER_NAME = "Public-Key-Pins".freeze
    REPORT_ONLY = "Public-Key-Pins-Report-Only".freeze
    HASH_ALGORITHMS = [:sha256].freeze


    class << self
      # Public: make an hpkp header name, value pair
      #
      # Returns nil if not configured, returns header name and value if configured.
      def make_header(config, user_agent = nil)
        return if config.nil? || config == OPT_OUT
        header = new(config)
        [header.name, header.value]
      end

      def validate_config!(config)
        return if config.nil? || config == OPT_OUT
        raise PublicKeyPinsConfigError.new("config must be a hash.") unless config.is_a? Hash

        if !config[:max_age]
          raise PublicKeyPinsConfigError.new("max-age is a required directive.")
        elsif config[:max_age].to_s !~ /\A\d+\z/
          raise PublicKeyPinsConfigError.new("max-age must be a number.
                                            #{config[:max_age]} was supplied.")
        elsif config[:pins] && config[:pins].length < 2
          raise PublicKeyPinsConfigError.new("A minimum of 2 pins are required.")
        end
      end
    end

    def initialize(config)
      @max_age = config.fetch(:max_age, nil)
      @pins = config.fetch(:pins, nil)
      @report_uri = config.fetch(:report_uri, nil)
      @report_only = !!config.fetch(:report_only, nil)
      @include_subdomains = !!config.fetch(:include_subdomains, nil)
    end

    def name
      if @report_only
        REPORT_ONLY
      else
        HEADER_NAME
      end
    end

    def value
      [
        max_age_directive,
        pin_directives,
        report_uri_directive,
        subdomain_directive
      ].compact.join("; ").strip
    end

    def pin_directives
      return nil if @pins.nil?
      @pins.collect do |pin|
        pin.map do |token, hash|
          "pin-#{token}=\"#{hash}\"" if HASH_ALGORITHMS.include?(token)
        end
      end.join("; ")
    end

    def max_age_directive
      "max-age=#{@max_age}" if @max_age
    end

    def report_uri_directive
      "report-uri=\"#{@report_uri}\"" if @report_uri
    end

    def subdomain_directive
      @include_subdomains ? "includeSubDomains" : nil
    end
  end
end
