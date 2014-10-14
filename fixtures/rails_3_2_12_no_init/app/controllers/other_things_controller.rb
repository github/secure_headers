class OtherThingsController < ApplicationController
  ensure_security_headers :csp => {:default_src => 'self', :disable_fill_missing => true}
  def index

  end
end
