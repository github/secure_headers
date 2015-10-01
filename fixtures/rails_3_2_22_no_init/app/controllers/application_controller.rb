class ApplicationController < ActionController::Base
  protect_from_forgery
  ensure_security_headers :csp => false
end
