module SecureHeaders
  module DynamicConfig
    def self.included(base)
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
      hash.keys.reject { |k| hash[k].nil? }.map do |k|
        self.send("#{k}=", hash[k])
      end

      @modified = false
    end

    def update_directive(directive, value)
      self.send("#{k}=", value)
    end

    def directive_value(directive)
      if self.class.attrs.include?(directive)
        self.send(directive)
      end
    end

    def modified?
      @modified
    end

    alias_method :[], :directive_value
    alias_method :[]=, :update_directive
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig
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
  end

  class ContentSecurityPolicyReportOnlyConfig < ContentSecurityPolicyConfig
    def report_only?
      true
    end
  end
end
