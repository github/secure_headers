require 'pry' unless defined? Pry
require 'pry-remote'

module PryRemote
  class Server
    # Override the call to Pry.start to save off current Server, pass a
    # pry_remote flag so pry-nav knows this is a remote session, and not kill
    # the server right away
    def run
      if PryNav.current_remote_server
        raise 'Already running a pry-remote session!'
      else
        PryNav.current_remote_server = self
      end

      setup
      Pry.start(
        @object,
        input: client.input_proxy,
        output: client.output,
        pry_remote: true,
      )
    end

    # Override to reset our saved global current server session.
    alias teardown_without_pry_nav teardown
    def teardown_with_pry_nav
      teardown_without_pry_nav
      PryNav.current_remote_server = nil
    end
    alias teardown teardown_with_pry_nav
  end
end

# Ensure cleanup when a program finishes without another break. For example,
# 'next' on the last line of a program never hits the tracer proc, and thus
# PryNav::Tracer#run doesn't have a chance to cleanup.
at_exit do
  set_trace_func nil
  PryNav.current_remote_server.teardown if PryNav.current_remote_server
end
