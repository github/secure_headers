# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      class RailsRenderObjectCollection < Base
        MSG = "Avoid `render object:`"

        def_node_matcher :render_with_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...) ...)
        PATTERN

        def_node_matcher :partial_key?, <<-PATTERN
          (pair (sym :partial) $_)
        PATTERN

        def_node_matcher :object_key?, <<-PATTERN
          (pair (sym ${:object :collection :spacer_template}) $_)
        PATTERN

        def on_send(node)
          if option_pairs = render_with_options?(node)
            partial_pair = option_pairs.detect { |pair| partial_key?(pair) }
            object_pair  = option_pairs.detect { |pair| object_key?(pair) }

            if partial_pair && object_pair
              partial_name = partial_key?(partial_pair)
              object_sym, object_node = object_key?(object_pair)

              case object_sym
              when :object
                if partial_name.children[0].is_a?(String)
                  suggestion = ", instead `render partial: #{partial_name.source}, locals: { #{File.basename(partial_name.children[0], '.html.erb')}: #{object_node.source} }`"
                end
                add_offense(node, message: "Avoid `render object:`#{suggestion}")
              when :collection, :spacer_template
                add_offense(node, message: "Avoid `render collection:`")
              end
            end
          end
        end
      end
    end
  end
end
