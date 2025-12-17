# frozen_string_literal: true

require "rubocop"
require "rubocop/github"
require "rubocop/github/inject"

RuboCop::GitHub::Inject.default_defaults!

require "rubocop/cop/github/avoid_object_send_with_dynamic_method"
require "rubocop/cop/github/insecure_hash_algorithm"
