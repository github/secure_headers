# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      class RailsViewRenderShorthand < Base
        extend AutoCorrector

        MSG = "Prefer `render` partial shorthand"

        def_node_matcher :render_with_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...))
        PATTERN

        def_node_matcher :partial_key?, <<-PATTERN
          (pair (sym :partial) $(str _))
        PATTERN

        def_node_matcher :locals_key?, <<-PATTERN
          (pair (sym :locals) $_)
        PATTERN

        def on_send(node)
          if option_pairs = render_with_options?(node)
            partial_key = option_pairs.map { |pair| partial_key?(pair) }.compact.first
            locals_key = option_pairs.map { |pair| locals_key?(pair) }.compact.first

            if option_pairs.length == 1 && partial_key
              add_offense(node, message: "Use `render #{partial_key.source}` instead") do |corrector|
                corrector.replace(node.source_range, "render #{partial_key.source}")
              end
            elsif option_pairs.length == 2 && partial_key && locals_key
              add_offense(node, message: "Use `render #{partial_key.source}, #{locals_key.source}` instead") do |corrector|
                corrector.replace(node.source_range, "render #{partial_key.source}, #{locals_key.source}")
              end
            end
          end
        end
      end
    end
  end
end
