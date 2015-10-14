module SecureHeaders
  class Header
    class << self
      def validate_config?
        ENV["RAILS_ENV"] == "development"
      end
    end
  end
end
