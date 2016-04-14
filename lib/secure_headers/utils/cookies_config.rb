module SecureHeaders
  class CookiesConfig

    attr_reader :config

    def initialize(config)
      @config = config
    end

    def validate!
      return if config.nil? || config == SecureHeaders::OPT_OUT

      validate_config!
      validate_secure_config! if config[:secure]
      validate_httponly_config! if config[:httponly]
      validate_samesite_config! if config[:samesite]
    end

    private

    def validate_config!
      raise CookiesConfigError.new("config must be a hash.") unless is_hash?(config)
    end

    def validate_secure_config!
      validate_hash_or_boolean!(:secure)
      validate_exclusive_use_of_hash_constraints!(config[:secure], :secure)
    end

    def validate_httponly_config!
      validate_hash_or_boolean!(:httponly)
      validate_exclusive_use_of_hash_constraints!(config[:httponly], :httponly)
    end

    def validate_samesite_config!
      raise CookiesConfigError.new("samesite cookie config must be a hash") unless is_hash?(config[:samesite])

      validate_samesite_boolean_config!
      validate_samesite_hash_config!
    end

    # when configuring with booleans, only one enforcement is permitted
    def validate_samesite_boolean_config!
      if config[:samesite].key?(:lax) && config[:samesite][:lax].is_a?(TrueClass) && config[:samesite].key?(:strict)
        raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
      elsif config[:samesite].key?(:strict) && config[:samesite][:strict].is_a?(TrueClass) && config[:samesite].key?(:lax)
        raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
      end
    end

    def validate_samesite_hash_config!
      # validate Hash-based samesite configuration
      if is_hash?(config[:samesite][:lax])
        validate_exclusive_use_of_hash_constraints!(config[:samesite][:lax], 'samesite lax')

        if is_hash?(config[:samesite][:strict])
          validate_exclusive_use_of_hash_constraints!(config[:samesite][:strict], 'samesite strict')
          validate_exclusive_use_of_samesite_enforcement!(:only)
          validate_exclusive_use_of_samesite_enforcement!(:except)
        end
      end
    end

    def validate_hash_or_boolean!(attribute)
      if !(is_hash?(config[attribute]) || is_boolean?(config[attribute]))
        raise CookiesConfigError.new("#{attribute} cookie config must be a hash or boolean")
      end
    end

    # validate exclusive use of only or except but not both at the same time
    def validate_exclusive_use_of_hash_constraints!(conf, attribute)
      return unless is_hash?(conf)

      if conf.key?(:only) && conf.key?(:except)
        raise CookiesConfigError.new("#{attribute} cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
      end
    end

    # validate exclusivity of only and except members within strict and lax
    def validate_exclusive_use_of_samesite_enforcement!(attribute)
      if (intersection = (config[:samesite][:lax].fetch(attribute, []) & config[:samesite][:strict].fetch(attribute, []))).any?
        raise CookiesConfigError.new("samesite cookie config is invalid, cookie(s) #{intersection.join(', ')} cannot be enforced as lax and strict")
      end
    end

    def is_hash?(obj)
      obj && obj.is_a?(Hash)
    end

    def is_boolean?(obj)
      obj && (obj.is_a?(TrueClass) || obj.is_a?(FalseClass))
    end
  end
end
