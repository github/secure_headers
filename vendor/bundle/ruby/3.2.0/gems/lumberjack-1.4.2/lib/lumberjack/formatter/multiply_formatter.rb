# frozen_string_literal: true

module Lumberjack
  class Formatter
    # This formatter can be used to multiply a numeric value by a specified multiplier and
    # optionally round to a specified number of decimal places.
    class MultiplyFormatter
      # @param multiplier [Numeric] The multiplier to apply to the value.
      # @param decimals [Integer, nil] The number of decimal places to round the result to.
      #   If nil, no rounding is applied.
      def initialize(multiplier, decimals = nil)
        @multiplier = multiplier
        @decimals = decimals
      end

      def call(value)
        return value unless value.is_a?(Numeric)

        value *= @multiplier
        value = value.round(@decimals) if @decimals
        value
      end
    end
  end
end
