module SecureHeaders
  class CookiesConfig

    attr_reader :config

    def initialize(config)
      @config = config
    end

    def valid?
      return if config.nil? || config == OPT_OUT
      raise CookiesConfigError.new("config must be a hash.") unless config.is_a? Hash

      # secure and httponly - validate only boolean or Hash configuration
      [:secure, :httponly].each do |attribute|
        if config[attribute] && !(config[attribute].is_a?(Hash) || config[attribute].is_a?(TrueClass) || config[attribute].is_a?(FalseClass))
          raise CookiesConfigError.new("#{attribute} cookie config must be a hash or boolean")
        end
      end

      # secure and httponly - validate exclusive use of only or except but not both at the same time
      [:secure, :httponly].each do |attribute|
        if config[attribute].is_a?(Hash)
          if config[attribute].key?(:only) && config[attribute].key?(:except)
            raise CookiesConfigError.new("#{attribute} cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
          end

          if (intersection = (config[attribute].fetch(:only, []) & config[attribute].fetch(:only, []))).any?
            raise CookiesConfigError.new("#{attribute} cookie config is invalid, cookies #{intersection.join(', ')} cannot be enforced as lax and strict")
          end
        end
      end

      if config[:samesite]
        raise CookiesConfigError.new("samesite cookie config must be a hash") unless config[:samesite].is_a?(Hash)

        # when configuring with booleans, only one enforcement is permitted
        if config[:samesite].key?(:lax) && config[:samesite][:lax].is_a?(TrueClass) && config[:samesite].key?(:strict)
          raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
        elsif config[:samesite].key?(:strict) && config[:samesite][:strict].is_a?(TrueClass) && config[:samesite].key?(:lax)
          raise CookiesConfigError.new("samesite cookie config is invalid, combination use of booleans and Hash to configure lax and strict enforcement is not permitted.")
        end

        # validate Hash-based samesite configuration
        if config[:samesite].key?(:lax) && config[:samesite][:lax].is_a?(Hash)
          # validate exclusive use of only or except but not both at the same time
          if config[:samesite][:lax].key?(:only) && config[:samesite][:lax].key?(:except)
            raise CookiesConfigError.new("samesite lax cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
          end

          if config[:samesite].key?(:strict)
            # validate exclusivity of only and except members
            if (intersection = (config[:samesite][:lax].fetch(:only, []) & config[:samesite][:strict].fetch(:only, []))).any?
              raise CookiesConfigError.new("samesite cookie config is invalid, cookie(s) #{intersection.join(', ')} cannot be enforced as lax and strict")
            end

            if (intersection = (config[:samesite][:lax].fetch(:except, []) & config[:samesite][:strict].fetch(:except, []))).any?
              raise CookiesConfigError.new("samesite cookie config is invalid, cookie(s) #{intersection.join(', ')} cannot be enforced as lax and strict")
            end
          end
        end

        if config[:samesite].key?(:strict) && config[:samesite][:strict].is_a?(Hash)
          # validate exclusive use of only or except but not both at the same time
          if config[:samesite][:strict].key?(:only) && config[:samesite][:strict].key?(:except)
            raise CookiesConfigError.new("samesite strict cookie config is invalid, simultaneous use of conditional arguments `only` and `except` is not permitted.")
          end
        end
      end
    end
  end
end
