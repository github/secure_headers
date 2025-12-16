# frozen_string_literal: true

require "delegate"
require "forwardable"

module Lumberjack
  # Methods to make Lumberjack::Logger API compatible with ActiveSupport::TaggedLogger.
  module TaggedLoggerSupport
    class Formatter < DelegateClass(Lumberjack::Formatter)
      extend Forwardable
      def_delegators :@logger, :tagged, :push_tags, :pop_tags, :clear_tags!

      def initialize(formatter:, logger:)
        @logger = logger
        @formatter = formatter
        super(formatter)
      end

      def current_tags
        tags = @logger.instance_variable_get(:@tags)
        if tags.is_a?(Hash)
          Array(tags["tagged"])
        else
          []
        end
      end

      def tags_text
        tags = current_tags
        if tags.any?
          tags.collect { |tag| "[#{tag}] " }.join
        end
      end

      def __formatter
        @formatter
      end
    end

    # Compatibility with ActiveSupport::TaggedLogging which only supports adding tags as strings.
    # Tags will be added to the "tagged" key in the logger's tags hash as an array.
    def tagged(*tags, &block)
      tagged_values = Array(tag_value("tagged"))
      flattened_tags = tags.flatten.collect(&:to_s).reject do |tag|
        tag.respond_to?(:blank?) ? tag.blank? : tag.empty?
      end
      tagged_values += flattened_tags unless flattened_tags.empty?

      if block || in_tag_context?
        tag("tagged" => tagged_values, &block)
      else
        tag_globally("tagged" => tagged_values)
      end
    end

    def push_tags(*tags)
      tagged(*tags)
    end

    def pop_tags(size = 1)
      tagged_values = tag_value("tagged")
      return unless tagged_values.is_a?(Array)

      tagged_values = ((tagged_values.size > size) ? tagged_values[0, tagged_values.size - size] : nil)

      if in_tag_context?
        tag("tagged" => tagged_values)
      else
        tag_globally("tagged" => tagged_values)
      end
    end

    def clear_tags!
      if in_tag_context?
        tag("tagged" => nil)
      else
        tag_globally("tagged" => nil)
      end
    end
  end
end
