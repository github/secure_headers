class ThingsController < ApplicationController
  ensure_security_headers :csp => false
  def index
  end
end
