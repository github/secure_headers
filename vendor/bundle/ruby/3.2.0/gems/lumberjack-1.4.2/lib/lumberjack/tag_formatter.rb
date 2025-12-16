# frozen_string_literal: true

module Lumberjack
  # Class for formatting tags. You can register a default formatter and tag
  # name specific formatters. Formatters can be either `Lumberjack::Formatter`
  # objects or any object that responds to `call`.
  #
  # tag_formatter = Lumberjack::TagFormatter.new.default(Lumberjack::Formatter.new)
  # tag_formatter.add(["password", "email"]) { |value| "***" }
  # tag_formatter.add("finished_at", Lumberjack::Formatter::DateTimeFormatter.new("%Y-%m-%dT%H:%m:%S%z"))
  class TagFormatter
    def initialize
      @formatters = {}
      @class_formatters = {}
      @default_formatter = nil
    end

    # Add a default formatter applied to all tag values. This can either be a Lumberjack::Formatter
    # or an object that responds to `call` or a block.
    #
    # @param formatter [Lumberjack::Formatter, #call, nil] The formatter to use.
    #    If this is nil, then the block will be used as the formatter.
    # @return [Lumberjack::TagFormatter] self
    def default(formatter = nil, &block)
      formatter ||= block
      formatter = dereference_formatter(formatter)
      @default_formatter = formatter
      self
    end

    # Remove the default formatter.
    #
    # @return [Lumberjack::TagFormatter] self
    def remove_default
      @default_formatter = nil
      self
    end

    # Add a formatter for specific tag names or object classes. This can either be a Lumberjack::Formatter
    # or an object that responds to `call` or a block. The formatter will be applied if it matches either a tag name
    # or if the tag value is an instance of a registered class. Tag name formatters will take precedence
    # over class formatters. The default formatter will not be applied to a value if a tag formatter
    # is applied to it.
    #
    # Name formatters can be applied to nested hashes using dot syntax. For example, if you add a formatter
    # for "foo.bar", it will be applied to the value of the "bar" key in the "foo" tag if that value is a hash.
    #
    # Class formatters will be applied recursively to nested hashes and arrays.
    #
    # @param names_or_classes [String, Module, Array<String, Module>] The tag names or object classes
    #   to apply the formatter to.
    # @param formatter [Lumberjack::Formatter, #call, nil] The formatter to use.
    #    If this is nil, then the block will be used as the formatter.
    # @return [Lumberjack::TagFormatter] self
    #
    # @example
    #  tag_formatter.add("password", &:redact)
    def add(names_or_classes, formatter = nil, &block)
      formatter ||= block
      formatter = dereference_formatter(formatter)
      if formatter.nil?
        remove(key)
      else
        Array(names_or_classes).each do |key|
          if key.is_a?(Module)
            @class_formatters[key] = formatter
          else
            @formatters[key.to_s] = formatter
          end
        end
      end
      self
    end

    # Remove formatters for specific tag names. The default formatter will still be applied.
    #
    # @param names_or_classes [String, Module, Array<String, Module>] The tag names or classes to remove the formatter from.
    # @return [Lumberjack::TagFormatter] self
    def remove(names_or_classes)
      Array(names_or_classes).each do |key|
        if key.is_a?(Module)
          @class_formatters.delete(key)
        else
          @formatters.delete(key.to_s)
        end
      end
      self
    end

    # Remove all formatters.
    #
    # @return [Lumberjack::TagFormatter] self
    def clear
      @default_formatter = nil
      @formatters.clear
      self
    end

    # Format a hash of tags using the formatters
    #
    # @param tags [Hash] The tags to format.
    # @return [Hash] The formatted tags.
    def format(tags)
      return nil if tags.nil?
      if @default_formatter.nil? && @formatters.empty? && @class_formatters.empty?
        return tags
      end

      formatted_tags(tags)
    end

    private

    def formatted_tags(tags, skip_classes: nil, prefix: nil)
      formatted = {}

      tags.each do |name, value|
        name = name.to_s
        formatted[name] = formatted_tag_value(name, value, skip_classes: skip_classes, prefix: prefix)
      end

      formatted
    end

    def formatted_tag_value(name, value, skip_classes: nil, prefix: nil)
      prefixed_name = prefix ? "#{prefix}#{name}" : name
      using_class_formatter = false

      formatter = @formatters[prefixed_name]
      if formatter.nil? && (skip_classes.nil? || !skip_classes.include?(value.class))
        formatter = class_formatter(value.class)
        using_class_formatter = true if formatter
      end

      formatter ||= @default_formatter

      formatted_value = begin
        if formatter.is_a?(Lumberjack::Formatter)
          formatter.format(value)
        elsif formatter.respond_to?(:call)
          formatter.call(value)
        else
          value
        end
      rescue SystemStackError, StandardError => e
        error_message = e.class.name
        error_message = "#{error_message} #{e.message}" if e.message && e.message != ""
        warn("<Error formatting #{value.class.name}: #{error_message}>")
        "<Error formatting #{value.class.name}: #{error_message}>"
      end

      if formatted_value.is_a?(Enumerable)
        skip_classes ||= []
        skip_classes << value.class if using_class_formatter
        sub_prefix = "#{prefixed_name}."

        formatted_value = if formatted_value.is_a?(Hash)
          formatted_tags(formatted_value, skip_classes: skip_classes, prefix: sub_prefix)
        else
          formatted_value.collect do |item|
            formatted_tag_value(nil, item, skip_classes: skip_classes, prefix: sub_prefix)
          end
        end
      end

      formatted_value
    end

    def dereference_formatter(formatter)
      if formatter.is_a?(TaggedLoggerSupport::Formatter)
        formatter.__formatter
      elsif formatter.is_a?(Symbol)
        formatter_class_name = "#{formatter.to_s.gsub(/(^|_)([a-z])/) { |m| $~[2].upcase }}Formatter"
        Formatter.const_get(formatter_class_name).new
      else
        formatter
      end
    end

    def class_formatter(klass)
      formatter = @class_formatters[klass]
      return formatter if formatter

      formatters = @class_formatters.select { |k, _| klass <= k }
      return formatters.values.first if formatters.length <= 1

      superclass = klass.superclass
      while superclass
        formatter = formatters[superclass]
        return formatter if formatter
        superclass = superclass.superclass
      end

      formatters.values.first
    end
  end
end
