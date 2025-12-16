# frozen_string_literal: true

module Lumberjack
  # A context is used to store tags that are then added to all log entries within a block.
  class Context
    attr_reader :tags

    # @param parent_context [Context] A parent context to inherit tags from.
    def initialize(parent_context = nil)
      @tags = {}
      @tags.merge!(parent_context.tags) if parent_context
      @tag_context = TagContext.new(@tags)
    end

    # Set tags on the context.
    #
    # @param tags [Hash] The tags to set.
    # @return [void]
    def tag(tags)
      @tag_context.tag(tags)
    end

    # Get a context tag.
    #
    # @param key [String, Symbol] The tag key.
    # @return [Object] The tag value.
    def [](key)
      @tag_context[key]
    end

    # Set a context tag.
    #
    # @param key [String, Symbol] The tag key.
    # @param value [Object] The tag value.
    # @return [void]
    def []=(key, value)
      @tag_context[key] = value
    end

    # Remove tags from the context.
    #
    # @param keys [Array<String, Symbol>] The tag keys to remove.
    # @return [void]
    def delete(*keys)
      @tag_context.delete(*keys)
    end

    # Clear all the context data.
    #
    # @return [void]
    def reset
      @tags.clear
    end
  end
end
