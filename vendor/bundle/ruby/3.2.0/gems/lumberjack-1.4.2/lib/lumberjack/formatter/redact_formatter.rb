# frozen_string_literal: true

module Lumberjack
  class Formatter
    # Log sensitive information in a redacted format showing the firat and last
    # characters of the value, with the rest replaced by asterisks. The number of
    # characters shown is dependent onthe length of the value; short values will
    # not show any characters in order to avoid revealing too much information.
    class RedactFormatter
      def call(obj)
        return obj unless obj.is_a?(String)

        if obj.length > 8
          "#{obj[0..1]}#{"*" * (obj.length - 4)}#{obj[-2..-1]}"
        elsif obj.length > 5
          "#{obj[0]}#{"*" * (obj.length - 2)}#{obj[-1]}"
        else
          "*****"
        end
      end
    end
  end
end
