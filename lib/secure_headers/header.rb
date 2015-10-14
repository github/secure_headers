module SecureHeaders
  class Header
    class << self
      def validate_config?
        ["development", "test"].include?(ENV["RAILS_ENV"])
      end
    end
  end
end
