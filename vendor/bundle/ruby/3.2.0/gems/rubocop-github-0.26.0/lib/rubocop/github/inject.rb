# frozen_string_literal: true

module RuboCop
  module GitHub
    # Because RuboCop doesn't yet support plugins, we have to monkey patch in a
    # bit of our configuration. Borrowed from:
    # https://github.com/rubocop/rubocop-rails/blob/f36121946359615a26c9a941763abd1470693e8d/lib/rubocop/rails/inject.rb
    module Inject
      def self.default_defaults!
        _load_config(CONFIG_DEFAULT)
      end

      def self.rails_defaults!
        _load_config(CONFIG_RAILS)
      end

      def self._load_config(path)
        path = path.to_s
        hash = ConfigLoader.send(:load_yaml_configuration, path)
        config = Config.new(hash, path).tap(&:make_excludes_absolute)
        puts "configuration from #{path}" if ConfigLoader.debug?
        config = ConfigLoader.merge_with_default(config, path, unset_nil: false)
        ConfigLoader.instance_variable_set(:@default_configuration, config)
      end
    end
  end
end
