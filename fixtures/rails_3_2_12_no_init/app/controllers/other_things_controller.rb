class OtherThingsController < ApplicationController
  ensure_security_headers :csp => {:default_src => 'self', :disable_chrome_extension => true,
    :disable_fill_missing => true}
  def index

  end
end
