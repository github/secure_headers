require 'pry' unless defined? Pry

module PryNav
  Commands = Pry::CommandSet.new do
    block_command 'step', 'Step execution into the next line or method.' do |steps|
      check_file_context
      breakout_navigation :step, steps
    end

    block_command 'next', 'Execute the next line within the same stack frame.' do |lines|
      check_file_context
      breakout_navigation :next, lines
    end

    block_command 'continue', 'Continue program execution and end the Pry session.' do
      check_file_context
      run 'exit-all'
    end

    helpers do
      def breakout_navigation(action, times)
        pry_instance.binding_stack.clear     # Clear the binding stack.
        throw(
          :breakout_nav,              # Break out of the REPL loop and
          action: action,             #   signal the tracer.
          times: times,
        )
      end

      # Ensures that a command is executed in a local file context.
      def check_file_context
        unless PryNav.check_file_context(target)
          raise Pry::CommandError, 'Cannot find local context. Did you use `binding.pry`?'
        end
      end
    end
  end
end

Pry.commands.import PryNav::Commands
