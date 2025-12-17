# frozen_string_literal: true

module Lumberjack
  module Rack
    # Support for using the Rails ActionDispatch request id in the log.
    # The format is expected to be a random UUID and only the first chunk is used for terseness
    # if the abbreviated argument is true.
    #
    # @deprecated Use tags instead of request id for unit of work. Will be removed in version 2.0.
    class RequestId
      REQUEST_ID = "action_dispatch.request_id"

      def initialize(app, abbreviated = false)
        Lumberjack::Utils.deprecated("Lumberjack::Rack::RequestId", "Lumberjack::Rack::RequestId will be removed in version 2.0") do
          @app = app
          @abbreviated = abbreviated
        end
      end

      def call(env)
        request_id = env[REQUEST_ID]
        if request_id && @abbreviated
          request_id = request_id.split("-", 2).first
        end
        Lumberjack.unit_of_work(request_id) do
          @app.call(env)
        end
      end
    end
  end
end
