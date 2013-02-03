Rails.application.routes.draw do
  post SecureHeaders::ContentSecurityPolicy::FF_CSP_ENDPOINT => "content_security_policy#scribe"
end
