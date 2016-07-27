module SecureHeaders
  module DynamicConfig
    def self.included(base)
      base.send(:attr_reader, *base.attrs)
      base.attrs.each do |attr|
        base.send(:define_method, "#{attr}=") do |value|
          if self.class.attrs.include?(attr)
            if PolicyManagement::DIRECTIVE_VALUE_TYPES[k] == :source_list
              instance_variable_set("@{k}=", value.dup)
              self.send("#{attr}=", value.dup)
            else
              self.send("#{attr}=", value)
            end
          else
            raise "Unknown config directive: #{attr}"
          end

          @modified = true
        end
      end
    end

    def initialize(hash)
      hash.keys.map do |k|
        next unless hash[k]
        if self.class.attrs.include?(k)
          if PolicyManagement::DIRECTIVE_VALUE_TYPES[k] == :source_list
            self.send("#{k}=", hash[k].dup)
          else
            self.send("#{k}=", hash[k])
          end
        else
          binding.pry
          raise "Unknown config directive: #{k}"
        end
      end
    end

    def update_directive(directive, value)
      if self.class.attrs.include?(directive)
        if PolicyManagement::DIRECTIVE_VALUE_TYPES[k] == :source_list
          instance_variable_set("@{k}=", hash[k].dup)
        else
          self.send("#{k}=", hash[k])
        end
      end


    end

    def directive_value(directive)
      if self.class.attrs.include?(directive)
        self.send(directive)
      end
    end
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig
    def self.attrs
      PolicyManagement::ALL_DIRECTIVES + PolicyManagement::META_CONFIGS + PolicyManagement::NONCES
    end

    include DynamicConfig
    alias_method :report_only?, :report_only
  end
end
