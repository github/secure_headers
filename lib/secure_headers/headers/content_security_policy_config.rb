# frozen_string_literal: true
module SecureHeaders
  module DynamicConfig
    def initialize(hash)
      @base_uri = nil
      @block_all_mixed_content = nil
      @child_src = nil
      @connect_src = nil
      @default_src = nil
      @font_src = nil
      @form_action = nil
      @frame_ancestors = nil
      @frame_src = nil
      @img_src = nil
      @manifest_src = nil
      @media_src = nil
      @navigate_to = nil
      @object_src = nil
      @plugin_types = nil
      @prefetch_src = nil
      @preserve_schemes = nil
      @report_only = nil
      @report_uri = nil
      @require_sri_for = nil
      @sandbox = nil
      @script_nonce = nil
      @script_src = nil
      @style_nonce = nil
      @style_src = nil
      @worker_src = nil
      @upgrade_insecure_requests = nil
      @disable_nonce_backwards_compatibility = nil
      @disable_minification = nil

      from_hash(hash)
    end

    def update_directive(directive, value)
      self.send("#{directive}=", value)
    end

    def directive_value(directive)
      self.send(directive)
    end

    def merge(new_hash)
      new_config = self.dup
      new_config.send(:from_hash, new_hash)
      new_config
    end

    def merge!(new_hash)
      from_hash(new_hash)
    end

    def append(new_hash)
      from_hash(ContentSecurityPolicy.combine_policies(self.to_h, new_hash))
    end

    def to_h
      self.class::ATTRS.each_with_object({}) do |key, hash|
        value = self.send(key)
        hash[key] = value unless value.nil?
      end
    end

    def dup
      self.class.new(self.to_h)
    end

    def opt_out?
      false
    end

    def ==(o)
      self.class == o.class && self.to_h == o.to_h
    end

    alias_method :[], :directive_value
    alias_method :[]=, :update_directive

    private
    def from_hash(hash)
      hash.each_pair do |k, v|
        next if v.nil?
        write_attribute(k, v)
      end
    end

    def write_attribute(attr, value)
      value = value.dup if PolicyManagement::DIRECTIVE_VALUE_TYPES[attr] == :source_list
      attr_variable = "@#{attr}"
      send("#{attr}=", value)
    end
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig

    HEADER_NAME = "Content-Security-Policy".freeze

    ATTRS = PolicyManagement::ALL_DIRECTIVES + PolicyManagement::META_CONFIGS + PolicyManagement::NONCES

    attr_accessor *ATTRS

    include DynamicConfig

    # based on what was suggested in https://github.com/rails/rails/pull/24961/files
    DEFAULT = {
      default_src: %w('self' https:),
      font_src: %w('self' https: data:),
      img_src: %w('self' https: data:),
      object_src: %w('none'),
      script_src: %w(https:),
      style_src: %w('self' https: 'unsafe-inline')
    }

    def report_only?
      false
    end

    def make_report_only
      ContentSecurityPolicyReportOnlyConfig.new(self.to_h)
    end
  end

  class ContentSecurityPolicyReportOnlyConfig < ContentSecurityPolicyConfig
    HEADER_NAME = "Content-Security-Policy-Report-Only".freeze

    def report_only?
      true
    end

    def make_report_only
      self
    end
  end
end
