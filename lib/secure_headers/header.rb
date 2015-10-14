module SecureHeaders
  class Header
    class << self
      def symbol_to_hyphen_case sym
        sym.to_s.gsub('_', '-')
      end

      def validate_config?
        ["development", "test"].include?(ENV["RAILS_ENV"])
      end
    end
  end
end
