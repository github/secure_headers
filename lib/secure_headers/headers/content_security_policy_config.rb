module SecureHeaders
  module DynamicConfig
    def self.included(base)
      base.send(:attr_writer, :modified)
      base.send(:attr_reader, *base.attrs)
      base.attrs.each do |attr|
        base.send(:define_method, "#{attr}=") do |value|
          if self.class.attrs.include?(attr)
            value = value.dup if PolicyManagement::DIRECTIVE_VALUE_TYPES[attr] == :source_list
            prev_value = self.instance_variable_get("@#{attr}")
            self.instance_variable_set("@#{attr}", value)
            if prev_value != self.instance_variable_get("@#{attr}")
              @modified = true
            end
          else
            raise ContentSecurityPolicyConfigError, "Unknown config directive: #{attr}=#{value}"
          end
        end
      end
    end

    def initialize(hash)
      from_hash(hash)
      @modified = false
    end

    def update_directive(directive, value)
      self.send("#{directive}=", value)
    end

    def directive_value(directive)
      if self.class.attrs.include?(directive)
        self.send(directive)
      end
    end

    def modified?
      @modified
    end

    def merge(new_hash)
      ContentSecurityPolicy.combine_policies(self.to_h, new_hash)
    end

    def merge!(new_hash)
      from_hash(new_hash)
    end

    def append(new_hash)
      from_hash(ContentSecurityPolicy.combine_policies(self.to_h, new_hash))
    end

    def to_h
      self.class.attrs.each_with_object({}) do |key, hash|
        hash[key] = self.send(key)
      end.reject { |_, v| v.nil? }
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
      hash.keys.reject { |k| hash[k].nil? }.map do |k|
        if self.class.attrs.include?(k)
          self.send("#{k}=", hash[k])
        else
          raise ContentSecurityPolicyConfigError, "Unknown config directive: #{k}=#{hash[k]}"
        end
      end
    end
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig
    CONFIG_KEY = :csp
    HEADER_NAME = "Content-Security-Policy".freeze

    def self.attrs
      PolicyManagement::ALL_DIRECTIVES + PolicyManagement::META_CONFIGS + PolicyManagement::NONCES
    end

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
    CONFIG_KEY = :csp_report_only
    HEADER_NAME = "Content-Security-Policy-Report-Only".freeze

    def report_only?
      true
    end

    def make_report_only
      self
    end
  end
end
