Rails.application.routes.draw do
  match SecureHeaders::ContentSecurityPolicy::FF_CSP_ENDPOINT => "content_security_policy#scribe"
end