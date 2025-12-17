# frozen_string_literal: true

module RuboCop
  module GitHub
    PROJECT_ROOT   = Pathname.new(__dir__).parent.parent.expand_path.freeze
    CONFIG_DEFAULT = PROJECT_ROOT.join("config", "default_cops.yml").freeze
    CONFIG_RAILS = PROJECT_ROOT.join("config", "rails_cops.yml").freeze
  end
end
