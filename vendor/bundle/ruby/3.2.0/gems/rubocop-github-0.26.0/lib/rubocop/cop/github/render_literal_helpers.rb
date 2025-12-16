# frozen_string_literal: true
#
require "rubocop"

module RuboCop
  module Cop
    module GitHub
      module RenderLiteralHelpers
        extend NodePattern::Macros

        def_node_matcher :literal?, <<-PATTERN
          ({str sym true false nil?} ...)
        PATTERN

        def_node_matcher :render?, <<-PATTERN
          (send nil? {:render :render_to_string} ...)
        PATTERN

        def_node_matcher :render_literal?, <<-PATTERN
          (send nil? {:render :render_to_string} ({str sym} $_) $...)
        PATTERN

        def_node_matcher :render_with_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...) ...)
        PATTERN

        def_node_matcher :render_view_component_instance?, <<-PATTERN
          (send nil? {:render :render_to_string} (send _ :new ...) ...)
        PATTERN

        def_node_matcher :render_view_component_instance_with_content?, <<-PATTERN
          (send nil? {:render :render_to_string} (send (send _ :new ...) `:with_content ...))
        PATTERN

        def_node_matcher :render_view_component_collection?, <<-PATTERN
          (send nil? {:render :render_to_string} (send _ :with_collection ...) ...)
        PATTERN

        def_node_matcher :locals_key?, <<-PATTERN
          (pair (sym :locals) $_)
        PATTERN

        def hash_with_literal_keys?(hash)
          hash.children.all? { |child| child.pair_type? } &&
            hash.pairs.all? { |pair| literal?(pair.key) }
        end

        def render_view_component?(node)
          render_view_component_instance_with_content?(node) ||
            render_view_component_instance?(node) ||
            render_view_component_collection?(node)
        end
      end
    end
  end
end
