module SecureHeaders
  class WebkitContentSecurityPolicy < ContentSecurityPolicy
    module Constants
      WEBKIT_CSP_HEADER_NAME = 'X-WebKit-CSP'
    end
    include Constants

    def base_name
      WEBKIT_CSP_HEADER_NAME
    end
  end
end
