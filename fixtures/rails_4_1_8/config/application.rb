require File.expand_path('../boot', __FILE__)

require "action_controller/railtie"
require "sprockets/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)


module Rails418
  class Application < Rails::Application

  end
end
