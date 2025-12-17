# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module GitHub
      # Public: A Rubocop to discourage using methods like Object#send that allow you to dynamically call other
      # methods on a Ruby object, when the method being called is itself completely dynamic. Instead, explicitly call
      # methods by name.
      #
      # Examples:
      #
      #     # bad
      #     foo.send(some_variable)
      #
      #     # good
      #     case some_variable
      #     when "bar"
      #       foo.bar
      #     else
      #       foo.baz
      #     end
      #
      #     # fine
      #     foo.send(:bar)
      #     foo.public_send("some_method")
      #     foo.__send__("some_#{variable}_method")
      class AvoidObjectSendWithDynamicMethod < Base
        MESSAGE_TEMPLATE = "Avoid using Object#%s with a dynamic method name."
        SEND_METHODS = %i(send public_send __send__).freeze
        CONSTANT_TYPES = %i(sym str const).freeze

        def on_send(node)
          return unless send_method?(node)
          return if method_being_sent_is_constrained?(node)
          add_offense(source_range_for_method_call(node), message: MESSAGE_TEMPLATE % node.method_name)
        end

        private

        def send_method?(node)
          SEND_METHODS.include?(node.method_name)
        end

        def method_being_sent_is_constrained?(node)
          method_name_being_sent_is_constant?(node) || method_name_being_sent_is_dynamic_string_with_constants?(node)
        end

        def method_name_being_sent_is_constant?(node)
          method_being_sent = node.arguments.first
          # e.g., `worker.send(:perform)` or `base.send("extend", Foo)`
          CONSTANT_TYPES.include?(method_being_sent.type)
        end

        def method_name_being_sent_is_dynamic_string_with_constants?(node)
          method_being_sent = node.arguments.first
          return false unless method_being_sent.type == :dstr

          # e.g., `foo.send("can_#{action}?")`
          method_being_sent.child_nodes.any? { |child_node| CONSTANT_TYPES.include?(child_node.type) }
        end

        def source_range_for_method_call(node)
          begin_pos =
            if node.receiver # e.g., for `foo.send(:bar)`, `foo` is the receiver
              node.receiver.source_range.end_pos
            else # e.g., `send(:bar)`
              node.source_range.begin_pos
            end
          end_pos = node.loc.selector.end_pos
          Parser::Source::Range.new(processed_source.buffer, begin_pos, end_pos)
        end
      end
    end
  end
end
