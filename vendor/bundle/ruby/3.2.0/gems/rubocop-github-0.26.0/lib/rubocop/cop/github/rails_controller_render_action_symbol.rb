# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      class RailsControllerRenderActionSymbol < Base
        extend AutoCorrector

        MSG = "Prefer `render` with string instead of symbol"

        def_node_matcher :render_sym?, <<-PATTERN
          (send nil? {:render :render_to_string} $(sym _))
        PATTERN

        def_node_matcher :render_with_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...))
        PATTERN

        def_node_matcher :action_key?, <<-PATTERN
          (pair (sym {:action :template}) $(sym _))
        PATTERN

        def on_send(node)
          if sym_node = render_sym?(node)
            add_offense(sym_node) do |corrector|
              register_offense(sym_node, node)
            end
          elsif option_pairs = render_with_options?(node)
            option_pairs.each do |pair|
              if sym_node = action_key?(pair)
                register_offense(sym_node, node)
              end
            end
          end
        end

        private

        def register_offense(sym_node, node)
          add_offense(sym_node) do |corrector|
            corrector.replace(node.source_range, "\"#{node.children[0]}\"")
          end
        end
      end
    end
  end
end
