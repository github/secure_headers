# frozen_string_literal: true

module Lumberjack
  class Formatter
    # Round numeric values to a set number of decimal places. This is useful when logging
    # floating point numbers to reduce noise and rounding errors in the logs.
    class RoundFormatter
      def initialize(precision = 3)
        @precision = precision
      end

      def call(obj)
        if obj.is_a?(Numeric)
          obj.round(@precision)
        else
          obj
        end
      end
    end
  end
end
