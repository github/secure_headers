# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      class RailsControllerRenderShorthand < Base
        extend AutoCorrector

        MSG = "Prefer `render` template shorthand"

        def_node_matcher :render_with_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...))
        PATTERN

        def_node_matcher :action_key?, <<-PATTERN
          (pair (sym {:action :template}) $({str sym} _))
        PATTERN

        def_node_matcher :str, <<-PATTERN
          ({str sym} $_)
        PATTERN

        def on_send(node)
          if option_pairs = render_with_options?(node)
            option_pairs.each do |pair|
              if value_node = action_key?(pair)
                comma = option_pairs.length > 1 ? ", " : ""
                corrected_source = node.source
                  .sub(/#{pair.source}(,\s*)?/, "")
                  .sub("render ", "render \"#{str(value_node)}\"#{comma}")

                add_offense(node, message: "Use `#{corrected_source}` instead") do |corrector|
                  corrector.replace(node.source_range, corrected_source)
                end
              end
            end
          end
        end
      end
    end
  end
end
