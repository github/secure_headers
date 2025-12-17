# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      class RailsViewRenderPathsExist < Base
        def_node_matcher :render?, <<-PATTERN
          (send nil? {:render :render_to_string} $...)
        PATTERN

        def_node_matcher :render_str?, <<-PATTERN
          (send nil? {:render :render_to_string} $(str $_) ...)
        PATTERN

        def_node_matcher :render_options?, <<-PATTERN
          (send nil? {:render :render_to_string} (hash $...))
        PATTERN

        def_node_matcher :partial_key?, <<-PATTERN
          (pair (sym :partial) $(str $_))
        PATTERN

        def on_send(node)
          return unless cop_config["ViewPath"]

          if args = render_str?(node)
            node, path = args
            unless resolve_partial(path.to_s)
              add_offense(node, message: "Partial template could not be found")
            end
          elsif pairs = render_options?(node)
            if pair = pairs.detect { |p| partial_key?(p) }
              node, path = partial_key?(pair)

              unless resolve_partial(path.to_s)
                add_offense(node, message: "Partial template could not be found")
              end
            end
          end
        end

        def resolve_partial(path)
          parts = path.split(File::SEPARATOR)
          parts << "_#{parts.pop}"
          path = parts.join(File::SEPARATOR)

          cop_config["ViewPath"].each do |view_path|
            if m = Dir[File.join(config.path_relative_to_config(view_path), path) + "*"].first
              return m
            end
          end
          nil
        end
      end
    end
  end
end
