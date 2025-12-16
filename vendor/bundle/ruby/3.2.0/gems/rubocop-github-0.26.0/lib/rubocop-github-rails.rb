# frozen_string_literal: true

require "rubocop"
require "rubocop/github"
require "rubocop/github/inject"

RuboCop::GitHub::Inject.rails_defaults!

require "rubocop/cop/github/rails_controller_render_action_symbol"
require "rubocop/cop/github/rails_controller_render_literal"
require "rubocop/cop/github/rails_controller_render_paths_exist"
require "rubocop/cop/github/rails_controller_render_shorthand"
require "rubocop/cop/github/rails_render_object_collection"
require "rubocop/cop/github/rails_view_render_literal"
require "rubocop/cop/github/rails_view_render_paths_exist"
require "rubocop/cop/github/rails_view_render_shorthand"
