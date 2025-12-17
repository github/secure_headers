require 'pry' unless defined? Pry
require 'pry-nav/tracer'

class << Pry
  alias start_without_pry_nav start

  def start_with_pry_nav(target = TOPLEVEL_BINDING, options = {})
    old_options = options.reject { |k, _| k == :pry_remote }

    if target.is_a?(Binding) && PryNav.check_file_context(target)
      # Wrap the tracer around the usual Pry.start
      PryNav::Tracer.new(options).run do
        start_without_pry_nav(target, old_options)
      end
    else
      # No need for the tracer unless we have a file context to step through
      start_without_pry_nav(target, old_options)
    end
  end

  alias start start_with_pry_nav
end
