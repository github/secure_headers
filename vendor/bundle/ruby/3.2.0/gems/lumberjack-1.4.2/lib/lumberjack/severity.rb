# frozen_string_literal: true

module Lumberjack
  # The standard severity levels for logging messages.
  module Severity
    # Backward compatibilty with 1.0 API
    DEBUG = ::Logger::Severity::DEBUG
    INFO = ::Logger::Severity::INFO
    WARN = ::Logger::Severity::WARN
    ERROR = ::Logger::Severity::ERROR
    FATAL = ::Logger::Severity::FATAL
    UNKNOWN = ::Logger::Severity::UNKNOWN

    SEVERITY_LABELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

    class << self
      # Convert a severity level to a label.
      #
      # @param [Integer] severity The severity level to convert.
      # @return [String] The severity label.
      def level_to_label(severity)
        SEVERITY_LABELS[severity] || SEVERITY_LABELS.last
      end

      # Convert a severity label to a level.
      #
      # @param [String, Symbol] label The severity label to convert.
      # @return [Integer] The severity level.
      def label_to_level(label)
        SEVERITY_LABELS.index(label.to_s.upcase) || UNKNOWN
      end

      # Coerce a value to a severity level.
      #
      # @param [Integer, String, Symbol] value The value to coerce.
      # @return [Integer] The severity level.
      def coerce(value)
        if value.is_a?(Integer)
          value
        else
          label_to_level(value)
        end
      end
    end
  end
end
