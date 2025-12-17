require 'pry' unless defined? Pry

module PryNav
  class Tracer
    def initialize(pry_start_options = {})
      @step_in_lines = -1                      # Break after this many lines
      @frames_when_stepping = nil              # Only break at this frame level
      @frames = 0                              # Traced stack frame level
      @pry_start_options = pry_start_options   # Options to use for Pry.start
    end

    def run
      # For performance, disable any tracers while in the console.
      stop

      return_value = nil
      command = catch(:breakout_nav) do      # Coordinates with PryNav::Commands
        return_value = yield
        {}    # Nothing thrown == no navigational command
      end

      # Adjust tracer based on command
      if process_command(command)
        start
      else
        if @pry_start_options[:pry_remote] && PryNav.current_remote_server
          PryNav.current_remote_server.teardown
        end
      end

      return_value
    end

    def start
      set_trace_func method(:tracer).to_proc
    end

    def stop
      set_trace_func nil
    end

    def process_command(command = {})
      times = (command[:times] || 1).to_i
      times = 1 if times <= 0

      case command[:action]
      when :step
        @step_in_lines = times
        @frames_when_stepping = nil
        true
      when :next
        @step_in_lines = times
        @frames_when_stepping = @frames
        true
      else
        false
      end
    end

    private

    def tracer(event, file, _line, _id, binding, _klass)
      # Ignore traces inside pry-nav code
      return if file && TRACE_IGNORE_FILES.include?(File.expand_path(file))

      case event
      when 'line'
        # Are we stepping? Or continuing by line ('next') and we're at the right
        # frame? Then decrement our line counter cause this line counts.
        if !@frames_when_stepping || @frames == @frames_when_stepping
          @step_in_lines -= 1
          @step_in_lines = -1 if @step_in_lines < 0

        # Did we go up a frame and not break for a 'next' yet?
        elsif @frames < @frames_when_stepping
          @step_in_lines = 0   # Break right away
        end

        # Break on this line?
        Pry.start(binding, @pry_start_options) if @step_in_lines.zero?

      when 'call', 'class'
        @frames += 1         # Track entering a frame

      when 'return', 'end'
        @frames -= 1         # Track leaving a stack frame
        @frames = 0 if @frames < 0
      end
    end
  end
end
