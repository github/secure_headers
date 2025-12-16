require 'bundler/setup'
require 'test/unit'

# lets make sure it works will all of the pry extensions
Bundler.require

class NavSample
  def nested_bind_with_call
    Pry.start(binding)
    nested_bind_call
    puts "root_puts"
  end

  def nested_bind_call
    puts "nested_puts"
  end
end

# lifted from:
# https://github.com/pry/pry-stack_explorer/blob/e3e6bd202e092712900f0d5f239ee21ab2f32b2b/test/support/input_tester.rb

class InputTester
  def initialize(*actions)
    if actions.last.is_a?(Hash) && actions.last.keys == [:history]
      @hist = actions.pop[:history]
    end

    @orig_actions = actions.dup
    @actions = actions
  end

  def readline(*)
    @actions.shift.tap{ |line| @hist << line if @hist }
  end

  def rewind
    @actions = @orig_actions.dup
  end
end