# frozen_string_literal: true

module Lumberjack
  class Formatter
    # Format an object by calling +inspect+ on it.
    class InspectFormatter
      def call(obj)
        obj.inspect
      end
    end
  end
end
