class OtherThingsController < ApplicationController
  ensure_security_headers :csp => {:default_src => 'self', :disable_chrome_extension => true,
    :disable_fill_missing => true, :script_src => 'nonce'}
  def index

  end
end
