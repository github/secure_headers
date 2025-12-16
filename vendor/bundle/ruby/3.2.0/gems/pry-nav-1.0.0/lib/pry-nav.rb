require 'pry-nav/version'
require 'pry-nav/pry_ext'
require 'pry-nav/commands'
require 'pry-nav/tracer'

# Optionally load pry-remote monkey patches
require 'pry-nav/pry_remote_ext' if defined? PryRemote

module PryNav
  TRACE_IGNORE_FILES = Dir[File.join(File.dirname(__FILE__), '**', '*.rb')].map { |f| File.expand_path(f) }

  extend self

  # Checks that a binding is in a local file context. Extracted from
  # https://github.com/pry/pry/blob/master/lib/pry/default_commands/context.rb
  def check_file_context(target)
    file = if target.respond_to?(:source_location)
      target.source_location.first
    else
      target.eval('__FILE__')
    end

    file == Pry.eval_path || (file !~ /(\(.*\))|<.*>/ && file != '' && file != '-e')
  end

  # Reference to currently running pry-remote server. Used by the tracer.
  attr_accessor :current_remote_server
end
