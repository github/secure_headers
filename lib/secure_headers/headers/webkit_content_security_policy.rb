module SecureHeaders
  class WebkitContentSecurityPolicy < ContentSecurityPolicy
    def base_name
      WEBKIT_CSP_HEADER_NAME
    end
  end
end
