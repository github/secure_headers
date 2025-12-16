# frozen_string_literal: true

module Lumberjack
  module Rack
    # Middleware to create a global context for Lumberjack for the scope of a rack request.
    #
    # The optional `env_tags` parameter can be used to set up global tags from the request
    # environment. This is useful for setting tags that are relevant to the entire request
    # like the request id, host, etc.
    class Context
      # @param [Object] app The rack application.
      # @param [Hash] env_tags A hash of tags to set from the request environment. If a tag value is
      #   a Proc, it will be called with the request `env` as an argument to allow dynamic tag values
      #   based on request data.
      def initialize(app, env_tags = nil)
        @app = app
        @env_tags = env_tags
      end

      def call(env)
        Lumberjack.context do
          apply_tags(env) if @env_tags
          @app.call(env)
        end
      end

      private

      def apply_tags(env)
        tags = @env_tags.transform_values do |value|
          value.is_a?(Proc) ? value.call(env) : value
        end
        Lumberjack.tag(tags)
      end
    end
  end
end
